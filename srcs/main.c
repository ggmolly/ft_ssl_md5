#include "ft_ssl.h"
#include <fcntl.h>
#include <unistd.h>

/**
 * @brief Passes the argument to the crypto context, when -s flag is used.
 * 
 * @note Asserts that arg (argv[2]) is not NULL & is not a file.
 * 
 * @param ctx Crypto context (contains the hash function)
 * @param arg 
 */
void parse_arg_input(t_context *ctx, char *arg) {
    ctx->known_size = strlen(arg);
    for (u64 i = 0; i < ctx->known_size; i += BUFFER_SIZE) {
        i32 buffer_length = ctx->known_size - i;
        if (buffer_length > BUFFER_SIZE) {
            buffer_length = BUFFER_SIZE;
        }
        // Copy bytes from the buffer to the internal buffer
        ctx_chomp(ctx, (byte *)arg + i, buffer_length);
        // Process the buffer
        ctx->digest_fn(ctx);
    }
    if (ctx->known_size % BUFFER_SIZE == 0) {
        ctx->buffer_size = 0;
        ctx->final_fn(ctx);
    }

    for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
        printf("%02x", ctx->digest[i]);
    }
}

/**
 * @brief Passes the passed file to the crypto context, when -s flag is not used, and a file is passed.
 * 
 * @note If path is NULL, the function will read from stdin.
 * 
 * @param ctx Crypto context (contains the hash function)
 * @param path Path to the file to hash
*/
void parse_file_input(t_context *ctx, char *path) {
    int fd = 0; // default to stdin
    if (path != NULL) { // if path was specified, open the file for reading
        fd = open(path, O_RDONLY);
    }
    if (fd == -1) {
        printf("ft_ssl: %s: %s\n", ERR_FILE_NOT_FOUND, path);
        return;
    }
    byte buffer[BUFFER_SIZE];
    i32 bytes_read = 0;
    // We have to know when we reach the end of the file, so we can call the final function
    bool eof = false;
    while (!eof) {
        bytes_read = read(fd, buffer, BUFFER_SIZE);
        if (bytes_read == -1) {
            printf("ft_ssl: %s: %s\n", ERR_FILE_READ_FAILED, path);
            return;
        }
        if (bytes_read < BUFFER_SIZE) {
            eof = true;
        }
        ctx_chomp(ctx, buffer, bytes_read);
        ctx->digest_fn(ctx);
        if (eof) {
            ctx->final_fn(ctx);
        }
    }
    for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
        printf("%02x", ctx->digest[i]);
    }
    close(fd);
}

/**
 * @brief Parse the argument in the command line, and set the flags accordingly.
 * 
 * @param arg Argument to parse
 * @param flags Format bitmask
 * @return true Argument was parsed successfully
 * @return false An error occurred
 */
bool parse_arg(char *arg, u8 *flags) {
    u8 before = *flags;
    switch (arg[1])
    {
        case 'p':
            SET_FLAG(*flags, FLAG_P);
            break;
        case 'q':
            SET_FLAG(*flags, FLAG_Q);
            break;
        case 'r':
            SET_FLAG(*flags, FLAG_R);
            break;
        case 's':
            SET_FLAG(*flags, FLAG_S);
            break;
        default:
            printf("ft_ssl: %s: '%s'\n", ERR_INVALID_FLAG, arg);
            return (false);
            break;
    }
    if (before == *flags) {
        printf("ft_ssl: %s: '%s'\n", ERR_DUPLICATE_FLAG, arg);
        return (false);
    }
    return (true);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        printf("usage: %s command [flags] [file/string]", argv[0]);
        return (1);
    }

    u8 flags = 0;
    t_context crypto_ctx;
    char *arg = NULL;

    if (strncmp(argv[1], "md5\0", 4) == 0) {
        flags |= FLAG_ALG_MD5;
        crypto_ctx = md5_init(0);
    } else if (strncmp(argv[1], "sha256\0", 7) == 0) {
        flags |= FLAG_ALG_SHA256;
        crypto_ctx = sha256_init(0);
    } else {
        printf("ft_ssl: %s: '%s'\n", ERR_ALG_NOT_FOUND, argv[1]);
        return (1);
    }

    for (i32 i = 2; i < argc; i++) {
        if (argv[i][0] == '-') {
            parse_arg(argv[i], &flags);
        } else { // isn't a flag, nor a command, must be the file or string to hash
            if (arg != NULL) {
                printf("ft_ssl: %s: '%s'\n", ERR_INVALID_FLAG, argv[i]);
                return (1);
            }
            arg = argv[i];
        }
    }

    if (!IS_SET(flags, FLAG_ALG_MD5) && !IS_SET(flags, FLAG_ALG_SHA256)) {
        if (arg == NULL) {
            printf("ft_ssl: %s: no algorithm specified\n", ERR_INVALID_FLAG);
            return (1);
        } else {
            printf("ft_ssl: %s: '%s'\n", ERR_ALG_NOT_FOUND, arg);
            return (1);
        }
    }

    if (IS_SET(flags, FLAG_S)) {
        if (arg == NULL) {
            printf("ft_ssl: %s: -s flag requires an argument\n", ERR_INVALID_FLAG);
            return (1);
        }
        parse_arg_input(&crypto_ctx, arg);
    } else {
        parse_file_input(&crypto_ctx, arg);
    }
    return 0;
}
