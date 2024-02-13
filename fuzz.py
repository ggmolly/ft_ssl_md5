import string
import random
import hashlib
import subprocess
import os
import sys
from uuid import uuid4
from typing import Tuple
from threading import Thread, Lock

PRINT_LOCK = Lock()

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

random_string = lambda n: ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def get_output(args: list) -> str:
    return subprocess.check_output(args).decode().strip()

def fuzz(length: int = 1, mode: str = "file") -> Tuple[str, str, str, bool]:
    input = random_string(length)
    expected = md5(input)
    if mode == "file":
        file_id = str(uuid4())
        with open(f"./ramfs/{file_id}", "w") as f:
            f.write(input)
        got = get_output(["./ft_ssl", "md5", f"./ramfs/{file_id}"])
        os.remove(f"./ramfs/{file_id}")
    elif mode == "text":
        got = subprocess.check_output(["./ft_ssl", "md5", "-q", "-s", input]).decode().strip()
    return input, expected, got, expected == got

class FuzzingThread(Thread):
    def __init__(self, length: int, mode: str = "text"):
        global PRINT_LOCK
        super().__init__()
        self.length = length
        self.print_lock = PRINT_LOCK
        self.mode = mode
    def run(self):
        input, expected, got, equal = fuzz(self.length, mode=self.mode)
        with self.print_lock:
            if equal:
                print(f"[fuzz] length={str(self.length).ljust(5)}/65535, {expected} == {got} -> OK", end="\r", flush=True)
            else:
                print(f"[fuzz] length={str(self.length).ljust(5)}/65535, {expected} != {got} -> KO [{input}]", flush=True)
                exit(1)


if __name__ == "__main__":
    try:
        subprocess.check_call(["make"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        print("[!] compilation failed")
        exit(1)
    if len(sys.argv) != 2 or sys.argv[1] not in ["text", "file", "huge_file"]:
        print(f"Usage: {sys.argv[0]} [text|file|huge_file]")
        exit(1)
    if sys.argv[1] == "file" or sys.argv[1] == "huge_file":
        assert os.path.exists("./ramfs"), "ramfs not found, please create it using itempotent_ramfs.sh"
    if sys.argv[1] != "huge_file":
        for length in range(1, 65535, os.cpu_count()):
            threads = []
            for i in range(length, length+os.cpu_count()):
                threads.append(FuzzingThread(i, mode=sys.argv[1]))
            try:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            except KeyboardInterrupt:
                print("\n[!] interrupted by user")
                exit(0)
    else:
        lengths = [1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9]
        lengths = [int(i) for i in lengths]
        for length in lengths:
            with open(f"./ramfs/{length}", "w") as f:
                subprocess.check_call(["dd", "if=/dev/zero", f"of=./ramfs/{length}", "bs=1024", f"count={length}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            got = get_output(["./ft_ssl", "md5", f"./ramfs/{length}"])
            expected = get_output(["md5sum", f"./ramfs/{length}"]).split()[0]
            if got != expected:
                print(f"[fuzz] length={str(length).ljust(5)}/1e9, {expected} != {got} -> KO", flush=True)
                exit(1)
            else:
                print(f"[fuzz] length={str(length).ljust(5)}/1e9, {expected} == {got} -> OK", end="\r", flush=True)
            os.remove(f"./ramfs/{length}")
        print()