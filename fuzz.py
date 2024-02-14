import string
import random
import hashlib
import subprocess
import os
import sys
import argparse
from uuid import uuid4
from typing import Tuple
from threading import Thread, Lock

class FuzzingError(Exception):
    pass

CORPUSES = {
    "tiny": {
        "text": range(1, 65535, 72),
        "file": range(1, 65535, 1024),
        "huge_file": [1e6],
    },
    "small": {
        "text": range(1, 65535, 16),
        "file": range(1, 65535, 256),
        "huge_file": [1e3, 1e4, 1e5],
    },
    "medium": {
        "text": range(1, 65535, 8),
        "file": range(1, 65535, 64),
        "huge_file": [1e3, 1e4, 1e5, 1e6, 1e7],
    },
    "all": {
        "text": range(1, 65535, 1),
        "file": range(1, 65535, 1),
        "huge_file": [1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9],
    },
}

TEXT_CORPUS_MAX = 65535
FILE_CORPUS = [1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9]

PRINT_LOCK = Lock()
ERROR_LOCK = Lock()

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

random_string = lambda n: ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def get_output(args: list) -> Tuple[str, bool]:
    """
    returns the output, and whether it got killed by a signal or timed out
    timeout is 30s
    """
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, _ = p.communicate(timeout=30)
        return out.decode().strip(), p.returncode < 0
    except subprocess.TimeoutExpired:
        p.kill()
        return "", True

def fuzz(args: list, mode: str = "file", alg: str = "md5") -> Tuple[str, str, str, bool, bool]:
    base_args = ["./ft_ssl", alg, "-q"]
    base_args.extend(args) # contains -s '..' or just the file path
    if "file" in mode:
        our, crashed = get_output(base_args)
        their, _ = get_output(["md5sum" if alg == "md5" else "sha256sum", args[-1]])
        their = their.split()[0]
        return args[-1], their, our, their == our, crashed
    elif mode == "text":
        our, crashed = get_output(base_args)
        their = md5(args[-1]) if alg == "md5" else sha256(args[-1])
        return args[-1], their, our, their == our, crashed

class FuzzingThread(Thread):
    def __init__(self,
            mode: str = "text",
            alg: str = "md5",
            corpus: list = [], # list of generators
        ):
        global PRINT_LOCK
        super().__init__()
        self.print_lock = PRINT_LOCK
        self.mode = mode
        self.alg = alg
        self.corpus = corpus

    def create_file(self, length: int) -> str:
        file_id = str(uuid4())
        content = random_string(length)
        path = f"/tmp/{file_id}"
        with open(path, "w") as f:
            f.write(content)
        return path

    def run(self):
        for length in self.corpus:
            if self.mode == "text":
                input, expected, got, equal, crashed = fuzz(
                    ["-s", random_string(length)],
                    mode=self.mode,
                    alg=self.alg
                )
            else:
                length = int(length)
                path = self.create_file(length)
                input, expected, got, equal, crashed = fuzz(
                    [path],
                    mode=self.mode,
                    alg=self.alg
                )
                os.remove(path)
            with self.print_lock:
                # get first 20 bytes of input and 32 bytes of output
                trimmed_input = input if len(input) <= 20 else f"{input[:20]}... ({len(input)} bytes)"
                trimmed_output = got if len(got) <= 32 else f"{got[:32]}... ({len(got)} bytes)"
                if crashed:
                    print(f"[!] length={str(length).ljust(5)}/65535, crashed [{trimmed_input}]")
                    exit(1)
                if not equal:
                    print(f"[!] length={str(length).ljust(5)}/65535, {expected} != {trimmed_output} -> KO [{trimmed_input}]")
                    exit(1)

def run_fuzzer(chunked_corpus: list, mode: str = "text", alg: str = "md5"):
    threads = []
    for corpus in chunked_corpus:
        threads.append(FuzzingThread(mode=mode, alg=alg, corpus=corpus))
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[!] interrupted by user")
        exit(0)
    except:
        exit(2)


def _corpus_chunk(corpus: list) -> list:
    """returns a chunk of the corpus to be used by the fuzzing threads"""
    chunk_size = os.cpu_count()
    chunk = []
    for i in range(0, len(corpus), chunk_size):
        chunk.append(corpus[i:i+chunk_size])
    return chunk

if __name__ == "__main__":
    try:
        subprocess.check_call(["make"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        print("[!] compilation failed")
        exit(1)
    args = argparse.ArgumentParser()
    args.add_argument("alg", choices=["md5", "sha256"])
    args.add_argument("mode", choices=["text", "file", "huge_file"])
    args.add_argument("corpus", choices=CORPUSES.keys(), nargs="?", default="all")
    args = args.parse_args()

    selected_corpus = sys.argv[3] if len(sys.argv) > 3 else "all"

    chunked_corpus = _corpus_chunk(CORPUSES[selected_corpus][sys.argv[2]])
    run_fuzzer(chunked_corpus, mode=args.mode, alg=args.alg)
