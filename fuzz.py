import string
import random
import hashlib
import subprocess
import os
from typing import Tuple
from threading import Thread, Lock

PRINT_LOCK = Lock()

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def get_hash(s: str) -> str:
    out = subprocess.check_output(["./ft_ssl", "md5", "-s", s])
    return out.decode().strip()

random_string = lambda n: ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def fuzz(length: int = 1) -> Tuple[str, str, str, bool]:
    input = random_string(length)
    expected = md5(input)
    got = get_hash(input)
    return input, expected, got, expected == got

class FuzzingThread(Thread):
    def __init__(self, length: int):
        global PRINT_LOCK
        super().__init__()
        self.length = length
        self.print_lock = PRINT_LOCK
    def run(self):
        input, expected, got, equal = fuzz(self.length)
        with self.print_lock:
            if equal:
                print(f"[fuzz] length={str(self.length).ljust(5)}/65535, {expected} == {got} -> OK", end="\r", flush=True)
            else:
                print(f"[fuzz] length={str(self.length).ljust(5)}/65535, {expected} != {got} -> KO [{input}]", flush=True)
                exit(1)


if __name__ == "__main__":
    try:
        subprocess.check_call(["make"])
    except:
        print("[!] compilation failed")
        exit(1)
    for length in range(1, 65535, os.cpu_count()):
        threads = []
        for i in range(length, length+os.cpu_count()):
            threads.append(FuzzingThread(i))
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("\n[!] interrupted by user")
            exit(0)