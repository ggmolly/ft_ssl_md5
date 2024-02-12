#include "ft_ssl.h"

/**
 * @brief Passes the argument to the crypto context, when -s flag is used.
 * 
 * @note Asserts that arg (argv[2]) is not NULL & is not a file.
 * 
 * @param ctx Crypto context (contains the hash function)
 * @param arg 
 */
void parse_arg_input(t_context *ctx, char *arg) {
    i32 len = strlen(arg);
    for (i32 i = 0; i < len; i += BUFFER_SIZE) {
        i32 buffer_length = len - i;
        if (buffer_length > BUFFER_SIZE) {
            buffer_length = BUFFER_SIZE;
        }
        ctx->chomp_fn(ctx, (byte *)arg + i, buffer_length);
    }
    if (len % BUFFER_SIZE == 0) {
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
void parse_file_input(t_context *ctx, char *arg) {
    // TODO
    (void) ctx;
    (void) arg;
    return;
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

    for (i32 i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            parse_arg(argv[i], &flags);
        } else if (strncmp(argv[i], "md5", 3) == 0) {
            flags |= FLAG_ALG_MD5;
            crypto_ctx = md5_init(0);
        } else if (strncmp(argv[i], "sha256", 6) == 0) {
            flags |= FLAG_ALG_SHA256;
            // crypto_ctx = sha256_init(0);
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
