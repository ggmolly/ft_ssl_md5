# ft_ssl_md5

The `ft_ssl_md5` project is a reimplementation of the `md5` and `sha256` hashing algorithms. It allows you to hash both strings, files (and standard input).

I've tried my best to not use any dynamic allocation in this project, which is why I've used a fixed buffer size of 1024 bytes for reading files and standard input.

# Allowed functions

| Function | Description | Usage |
|----------|-------------|-------|
| `open`   | Open a file | To open any file with read permissions |
| `read`   | Read from a file | To read from a file / stdin |
| `close`  | Close a file | Close any opened file, to free the file descriptor |
| `write`  | Write to a file | To write to a file / stdout / stderr |
| `malloc` | Dynamic memory allocation | None, don't use it, it's bad. |
| `free`   | Frees previously allocated memory | - |

# Compilation

```bash
# https
git clone https://github.com/ggmolly/ft_ssl_md5
# ssh
# git clone git@github.com:ggmolly/ft_ssl_md5.git

cd ft_ssl_md5 && make
```

# Usage

| Flag | Description |
|------|-------------|
| `-p`   | Echo STDIN to STDOUT and append the hash to STDOUT |
| `-q`   | Quiet mode, prints only the hash |
| `-r`   | Reverse the format of the output |
| `-s`   | Print the sum of the given string |

```bash
# ./ft_ssl [md5|sha256] [-pqr] [-s string] [files ...]

$ ./ft_ssl md5 -s "Hello, World!"
"Hello, World!" (MD5) = 65a8e27d8879283831b664bd8b7f0ad4
$ ./ft_ssl sha256 -s "Hello, World!"
"Hello, World!" (SHA256) = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
$ echo "Hello, World!" | ./ft_ssl md5
(stdin)= bea8252ff4e80f41719ea13cdf007273
$ echo "Hello, World!" | ./ft_ssl sha256 -p
("Hello, World!") = c98c24b677eff44860afea6f493bbaec5bb1c4cbb209c6fc2bbb47f66ff2ad31
$ echo "Hello, World!" | ./ft_ssl sha256 -p -s a empty_file does_not_exists
("Hello, World!") = c98c24b677eff44860afea6f493bbaec5bb1c4cbb209c6fc2bbb47f66ff2ad31
SHA256 ("a") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
SHA256 (empty_file) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ft_ssl: file not found: 'does_not_exists'
$ echo "Hello, World!" | ./ft_ssl sha256 -p -r -s "a" empty_file 
("Hello, World!") = c98c24b677eff44860afea6f493bbaec5bb1c4cbb209c6fc2bbb47f66ff2ad31
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb "a"
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 empty_file
```

# Fuzzing

I've used a handmade fuzzing tool to test the robustness of my implementation. It checks if the output of my implementation matches the standard implementation of `md5` and `sha256` for a given input, for random inputs of length 1 to 65535.

The tool requires Python3, and uses `hashlib` along with `subprocess`.

> NOTE: The code is extremely dirty, it was just a quick and dirty tool to test my implementation.

## Modes

- `text`, passes the input to the `-s` flag, thus hashing the input as a string.
- `file`, writes the input to a file, and passes the file to the program, thus hashing the input as a file.
- `huge_file`, writes the input to a file, and passes the file to the program, file size ranges from 1 KB to 1 GB.

> WARNING: Both `file` and `huge_file` requires Linux, as their data is pulled from `/dev/zero`.

> WARNING: I recommend using a `ramfs`, you can create one with root privileges using the `idempotent_ramfs.sh` script.

## Usage

```bash
$ python3 fuzz.py [md5|sha256] [text|file|huge_file]
```

# References

- [RFC 1321](https://tools.ietf.org/html/rfc1321)
- [RFC 6234](https://tools.ietf.org/html/rfc6234)
- [Wikipedia MD5](https://en.wikipedia.org/wiki/MD5)
- [Wikipedia SHA-2](https://en.wikipedia.org/wiki/SHA-2)
- [Zunawe's MD5 implementation in C](https://github.com/unawe/md5-c), very helpful to debug my implementation.
- [EddieEldridge's SHA-256 implementation in C](https://github.com/EddieEldridge/SHA-256), also very helpful to debug my implementation.