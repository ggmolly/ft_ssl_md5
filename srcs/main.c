#include "ft_ssl.h"
#include <fcntl.h>
#include <unistd.h>

static const t_algorithm algorithms[] = {
    {"md5", md5_init, FLAG_ALG_MD5},
    {"sha256", sha256_init, FLAG_ALG_SHA256},
    {NULL, NULL, 0}
};

static const char* valid_flags[] = {
    "-p", "-q", "-r", "-s"
};

/**
 * @brief Passes the argument to the crypto context, when -s flag is used.
 * 
 * @note Asserts that arg (argv[2]) is not NULL & is not a file.
 * 
 * @param ctx Crypto context (contains the hash function)
 * @param arg 
 */
void parse_arg_input(t_context *ctx, char *arg) {
    ctx->known_size = ft_strlen(arg);
    for (u64 i = 0; i < ctx->known_size; i += BUFFER_SIZE) {
        i32 buffer_length = ctx->known_size - i;
        if (buffer_length > BUFFER_SIZE) {
            buffer_length = BUFFER_SIZE;
        }
        // Copy bytes from the buffer to the internal buffer
        ctx_chomp(ctx, (byte *)arg + i, buffer_length);
    }
    ctx->final_fn(ctx);
}

/**
 * @brief Passes the passed file to the crypto context, when -s flag is not used, and a file is passed.
 * 
 * @note If path is NULL, the function will read from stdin.
 * 
 * @param ctx Crypto context (contains the hash function)
 * @param path Path to the file to hash
 * @param flags If `-p` is true and path is NULL, will echo stdin to stdout
 * 
 * @return true File was read successfully, false otherwise
*/
bool parse_file_input(t_context *ctx, char *path, u8 flags) {
    int fd = 0; // default to stdin
    if (path != NULL) { // if path was specified, open the file for reading
        fd = open(path, O_RDONLY);
    }
    if (fd == -1) {
        print_error(ERR_FILE_NOT_FOUND, path);
        return (false);
    }
    byte buffer[BUFFER_SIZE];
    i32 bytes_read = 0;
    // We have to know when we reach the end of the file, so we can call the final function
    bool eof = false;
    bool echo = false;
    // If -p is set, and path is NULL, echo stdin to stdout
    echo = IS_SET(flags, FLAG_P) && path == NULL;
    if (echo && !IS_SET(flags, FLAG_Q)) {
        write(1, "(\"", 2);
    }
    while (!eof) {
        bytes_read = read(fd, buffer, BUFFER_SIZE);
        if (bytes_read == -1) {
            print_error(ERR_FILE_READ_FAILED, path);
            return (false);
        } else if (bytes_read == 0) {
            eof = true;
        } else {
            ctx_chomp(ctx, buffer, bytes_read);
        }
        // if eof, or known_size is known and we have read all the bytes, or if we read less than BUFFER_SIZE, strip the last '\n' if any
        if (echo &&
            (eof || (ctx->known_size != 0 && ctx->known_size == ctx->chomped_bytes + ctx->buffer_size) || bytes_read < BUFFER_SIZE)
        ) {
            if (buffer[bytes_read-1] == '\n' && !IS_SET(flags, FLAG_Q)) {
                bytes_read--;
            }
        }
        if (echo) {
            write(1, buffer, bytes_read);
        }
    }
    ctx->final_fn(ctx);
    if (echo && !IS_SET(flags, FLAG_Q)) {
        write(1, "\") = ", 5);
    }
    close(fd);
    return (true);
}

char *get_next_arg(i32 argc, char **argv, i32 offset) {
    return (offset < argc ? argv[offset] : NULL);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        write(2, "usage: ", 7);
        write(2, argv[0], ft_strlen(argv[0]));
        write(2, " command [flags] [file/string]\n", 30);
        return (1);
    }
    u8 flags = 0;
    t_context crypto_ctx;
    crypto_ctx.alg_name = NULL;

    // Find the algorithm that corresponds to the first argument
    for (i32 i = 0; algorithms[i].name != NULL; i++) {
        if (ft_strncmp(argv[1], algorithms[i].name, ft_strlen(algorithms[i].name)) == 0) {
            flags |= algorithms[i].flag;
            crypto_ctx = algorithms[i].init(0);
            break;
        }
    }

    // if no algorithm was found, print an error and return
    if (crypto_ctx.alg_name == NULL) {
        write(2, "ft_ssl: Error: '", 16);
        write(2, argv[1], ft_strlen(argv[1]));
        write(2, "' is an invalid command.\n\nCommands:\n", 36);
        for (i32 i = 0; algorithms[i].name != NULL; i++) {
            write(2, algorithms[i].name, ft_strlen(algorithms[i].name));
            write(2, "\n", 1);
        }
        write(2, "\nFlags:\n", 8);
        for (i32 i = 0; i < 4; i++) {
            write(2, valid_flags[i], ft_strlen(valid_flags[i]));
            write(2, " ", 1);
        }
        write(2, "\n", 1);
        return (1);
    }

    // Otherwise, we can parse the arguments
    i32 parameters = parse_parameters(argc, argv, &flags);
    // if -p was passed, read from stdin, or if only parameters were passed, read from stdin
    if (IS_SET(flags, FLAG_P)) {
        parse_file_input(&crypto_ctx, NULL, flags);
        ctx_print_digest(&crypto_ctx, NULL, false, flags);
    }

    // Consider the rest of the arguments as files, except -s and the following arguments
    for (i32 i = 2 + parameters; i < argc; i++) {
        crypto_ctx.reset_fn(&crypto_ctx);
        char *next = get_next_arg(argc, argv, i+1);
        // if the first argument we parse is -s
        if (i == 2 + parameters && IS_SET(flags, FLAG_S)) {
            if (next == NULL) { // no argument after -s, consider it as an error
                print_error(ERR_INVALID_FLAG, "no string specified after -s");
                return (1);
            } else {
                parse_arg_input(&crypto_ctx, next); // pass the string to the crypto context
                i++;
            }
        } else if (!parse_file_input(&crypto_ctx, argv[i], flags)) { // whatever the next argument is, it will be interpreted as a string
            continue; // skip to the next input, the error message has already been printed
        }
        // Print the digest & unset -s
        ctx_print_digest(&crypto_ctx, IS_SET(flags, FLAG_S) ? next : argv[i], !IS_SET(flags, FLAG_S), flags);
        UNSET_FLAG(flags, FLAG_S);
    }

    // If no arguments were passed, read from stdin
    if (argc == 2 + parameters && !IS_SET(flags, FLAG_P)) {
        parse_file_input(&crypto_ctx, NULL, flags);
        ctx_print_digest(&crypto_ctx, NULL, false, flags);
    }
    return 0;
}
