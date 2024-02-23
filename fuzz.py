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
    "subject": {}, # special case
}

PRINT_LOCK = Lock()

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

def run_args(args: list, stdin: str = "") -> str:
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    out, _ = p.communicate(stdin.encode())
    return out.decode().strip()

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
    if selected_corpus != "subject":
        chunked_corpus = _corpus_chunk(CORPUSES[selected_corpus][sys.argv[2]])
        run_fuzzer(chunked_corpus, mode=args.mode, alg=args.alg)
    else: # python3 fuzz.py md5 text subject
        # echo '42 is nice' | ./ft_ssl md5
        assert run_args(["./ft_ssl", "md5"], "42 is nice\n") == "(stdin) = 35f1d6de0302e2086a4e472266efb3a9"
        # echo '42 is nice' | ./ft_ssl md5 -p
        assert run_args(["./ft_ssl", "md5", "-p"], "42 is nice\n") == '("42 is nice") = 35f1d6de0302e2086a4e472266efb3a9'
        # echo "Pity the living." | ./ft_ssl md5 -q -r
        assert run_args(["./ft_ssl", "md5", "-q", "-r"], "Pity the living.\n") == "e20c3b973f63482a778f3fd1869b7f25"
        with open("file", "w") as f:
            f.write("And above all,\n")
        # ./ft_ssl md5 file
        assert run_args(["./ft_ssl", "md5", "file"]) == 'MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a'
        # ./ft_ssl md5 -r file
        assert run_args(["./ft_ssl", "md5", "-r", "file"]) == '53d53ea94217b259c11a5a2d104ec58a file'
        # ./ft_ssl md5 -s "pity those that aren't following baerista on spotify."
        assert run_args(["./ft_ssl", "md5", "-s", "pity those that aren't following baerista on spotify."]) == "MD5 (\"pity those that aren't following baerista on spotify.\") = a3c990a1964705d9bf0e602f44572f5f"
        # echo "be sure to handle edge cases carefully" | ./ft_ssl md5 -p file
        assert run_args(["./ft_ssl", "md5", "-p", "file"], "be sure to handle edge cases carefully\n") == '("be sure to handle edge cases carefully") = 3553dc7dc5963b583c056d1b9fa3349c\nMD5 (file) = 53d53ea94217b259c11a5a2d104ec58a'
        # echo "some of this will not make sense at first" | ./ft_ssl md5 file
        assert run_args(["./ft_ssl", "md5", "file"], "some of this will not make sense at first\n") == 'MD5 (file) = 53d53ea94217b259c11a5a2d104ec58a'
        # echo "but eventually you will understand" | ./ft_ssl md5 -p -r file
        assert run_args(["./ft_ssl", "md5", "-p", "-r", "file"], "but eventually you will understand\n") == '("but eventually you will understand") = dcdd84e0f635694d2a943fa8d3905281\n53d53ea94217b259c11a5a2d104ec58a file'
        # echo "GL HF let's go" | ./ft_ssl md5 -p -s "foo" file
        assert run_args(["./ft_ssl", "md5", "-p", "-s", "foo", "file"], "GL HF let's go\n") == '("GL HF let\'s go") = d1e3cc342b6da09480b27ec57ff243e2\nMD5 (\"foo\") = acbd18db4cc2f85cedef654fccc4a4d8\nMD5 (file) = 53d53ea94217b259c11a5a2d104ec58a'
        # echo "one more thing" | ./ft_ssl md5 -r -p -s "foo" file -s "bar"
        assert run_args(["./ft_ssl", "md5", "-r", "-p", "-s", "foo", "file", "-s", "bar"], "one more thing\n") == '("one more thing") = a0bd1876c6f011dd50fae52827f445f5\nacbd18db4cc2f85cedef654fccc4a4d8 "foo"\n53d53ea94217b259c11a5a2d104ec58a file\nft_ssl: file not found: \'-s\'\nft_ssl: file not found: \'bar\''
        # echo "just to be extra clear" | ./ft_ssl md5 -r -q -p -s "foo" file
        assert run_args(["./ft_ssl", "md5", "-r", "-q", "-p", "-s", "foo", "file"], "just to be extra clear\n") == 'just to be extra clear\n3ba35f1ea0d170cb3b9a752e3360286c\nacbd18db4cc2f85cedef654fccc4a4d8\n53d53ea94217b259c11a5a2d104ec58a'

        # Run the same commands with sha256 instead
        # echo '42 is nice' | ./ft_ssl sha256
        assert run_args(["./ft_ssl", "sha256"], "42 is nice\n") == "(stdin) = a5482539287a4069ebd3eb45a13a47b1968316c442a7e69bc6b9c100b101d65d"
        # echo '42 is nice' | ./ft_ssl sha256 -p
        assert run_args(["./ft_ssl", "sha256", "-p"], "42 is nice\n") == '("42 is nice") = a5482539287a4069ebd3eb45a13a47b1968316c442a7e69bc6b9c100b101d65d'
        # echo "Pity the living." | ./ft_ssl sha256 -q -r
        assert run_args(["./ft_ssl", "sha256", "-q", "-r"], "Pity the living.\n") == "40133cfe543247c1cae0ffb0003c1179ce9fb0046bee19f9fca167380643ba45"
        with open("file", "w") as f:
            f.write("And above all,\n")
        # ./ft_ssl sha256 file
        assert run_args(["./ft_ssl", "sha256", "file"]) == 'SHA256 (file) = f9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705'
        # ./ft_ssl sha256 -r file
        assert run_args(["./ft_ssl", "sha256", "-r", "file"]) == 'f9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705 file'
        # ./ft_ssl sha256 -s "pity those that aren't following baerista on spotify."
        assert run_args(["./ft_ssl", "sha256", "-s", "pity those that aren't following baerista on spotify."]) == "SHA256 (\"pity those that aren't following baerista on spotify.\") = 7838c25c9debff86c584245d67b429186d3850c89da31c0b49b8d0380a3e14bf"
        # echo "be sure to handle edge cases carefully" | ./ft_ssl sha256 -p file
        assert run_args(["./ft_ssl", "sha256", "-p", "file"], "be sure to handle edge cases carefully\n") == '("be sure to handle edge cases carefully") = ef9241f878a1da676104a81239792a2817bc0390a427ca20bad1a59030fd20c2\nSHA256 (file) = f9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705'
        # echo "some of this will not make sense at first" | ./ft_ssl sha256 file
        assert run_args(["./ft_ssl", "sha256", "file"], "some of this will not make sense at first\n") == 'SHA256 (file) = f9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705'
        # echo "but eventually you will understand" | ./ft_ssl sha256 -p -r file
        assert run_args(["./ft_ssl", "sha256", "-p", "-r", "file"], "but eventually you will understand\n") == '("but eventually you will understand") = 43da940057fd3b7453ee91b3a056a41343e6f0bce315570ed27e06c993a539da\nf9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705 file'
        # echo "GL HF let's go" | ./ft_ssl sha256 -p -s "foo" file
        assert run_args(["./ft_ssl", "sha256", "-p", "-s", "foo", "file"], "GL HF let's go\n") == '("GL HF let\'s go") = f33201f3d70c9dccccec022e2ff0df2006e016f153f600407917d14955fbec22\nSHA256 (\"foo\") = 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae\nSHA256 (file) = f9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705'
        # echo "one more thing" | ./ft_ssl sha256 -r -p -s "foo" file -s "bar"
        assert run_args(["./ft_ssl", "sha256", "-r", "-p", "-s", "foo", "file", "-s", "bar"], "one more thing\n") == '("one more thing") = 720bbf63077e0bea3b70c87954123daa6fcf32f973f4d646622bd016b140ec75\n2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae "foo"\nf9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705 file\nft_ssl: file not found: \'-s\'\nft_ssl: file not found: \'bar\''
        # echo "just to be extra clear" | ./ft_ssl sha256 -r -q -p -s "foo" file
        assert run_args(["./ft_ssl", "sha256", "-r", "-q", "-p", "-s", "foo", "file"], "just to be extra clear\n") == 'just to be extra clear\n41c3da28172faf72bb777d6a428b6d801427d02513c56cd9e3672f44383f8eee\n2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae\nf9eb9a5a063eb386a18525c074e1065c316ec434f911e0d7d59ba2d9fd134705'