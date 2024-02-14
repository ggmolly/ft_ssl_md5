#include "ft_ssl.h"
#include "unistd.h"

/**
 * @brief Copies BUFFER_SIZE bytes from the buffer to internal buffer
 * 
 * @param ctx Hash context
 * @param buf A not-sentinel-terminated buffer
 * @param n Number of bytes to eat, if the number of bytes is greater than BUFFER_SIZE, automatically digests
 */
void ctx_chomp(t_context *ctx, const byte *buf, u64 n) {
    // if the new buffer size is greater than BUFFER_SIZE, digest the buffer
    if (ctx->buffer_size + n > BUFFER_SIZE) {
        u64 to_copy = BUFFER_SIZE - ctx->buffer_size;
        ft_memcpy(ctx->buffer + ctx->buffer_size, buf, to_copy);
        ctx->chomped_bytes += to_copy;
        ctx->buffer_size += to_copy;
        ctx->digest_fn(ctx);
        ctx->buffer_size = 0;
        ctx_chomp(ctx, buf + to_copy, n - to_copy);
    } else {
        ft_memcpy(ctx->buffer + ctx->buffer_size, buf, n);
        ctx->chomped_bytes += n;
        ctx->buffer_size += n;
    }
}

/**
 * @brief Sets the stream as finished, and calls context's finalization function
 * 
 * @note Can be manually called, no-op if the stream is already finished
 * 
 * @param ctx Hash context
*/
void ctx_finish(t_context *ctx) {
    if (ctx->stream_finished) return;
    ctx->stream_finished = true;
    ctx->final_fn(ctx);
}

/**
 * @brief Writes the digest to an output buffer, must be at least ctx->digest_size bytes long
 * 
 * @note The buffer is not null-terminated
 * 
 * @param ctx Hash context
 * @param out Output buffer
 */
void ctx_hexdigest(t_context *ctx, unsigned char *out) {
    for (u64 i = 0; i < ctx->digest_size; i++) {
        out[i * 2] = "0123456789abcdef"[ctx->digest[i] >> 4];
        out[i * 2 + 1] = "0123456789abcdef"[ctx->digest[i] & 0x0F];
    }
    out[ctx->digest_size * 2] = '\0';
}

/**
 * @brief Prints the digest to the standard output
 * 
 * @param ctx Hash context
 * @param arg If not NULL, prints the argument, otherwise stdin
 * @param is_file If true, prints the filename, otherwise arg preceeded and succeeded by double quotes
*/
void ctx_print_digest(t_context *ctx, char *arg, bool is_file, u8 flags) {
    unsigned char digest[ctx->digest_size * 2 + 1];
    ctx_hexdigest(ctx, digest);
    if (IS_SET(flags, FLAG_Q)) {
        ft_putstr_fd(1, digest, ctx->digest_size * 2);
        ft_putstr_fd(1, "\n", 1);
        return ;
    }
    if (IS_SET(flags, FLAG_R)) {
        if (is_file) {
            ft_putstr_fd(1, digest, ctx->digest_size * 2);
            ft_putstr_fd(1, " ", 1);
            ft_putstr_fd(1, arg, ft_strlen(arg));
            ft_putstr_fd(1, "\n", 1);
        } else if (arg != NULL) {
            ft_putstr_fd(1, digest, ctx->digest_size * 2);
            ft_putstr_fd(1, " \"", 2);
            ft_putstr_fd(1, arg, ft_strlen(arg));
            ft_putstr_fd(1, "\"\n", 2);
        } else {
            ft_putstr_fd(1, digest, ctx->digest_size * 2);
            ft_putstr_fd(1, "\n", 1);
        }
        return ;
    } else {
        if (is_file) {
            ft_putstr_fd(1, ctx->alg_name, ft_strlen(ctx->alg_name));
            ft_putstr_fd(1, " (", 2);
            ft_putstr_fd(1, arg, ft_strlen(arg));
            ft_putstr_fd(1, ") = ", 4);
            ft_putstr_fd(1, digest, ctx->digest_size * 2);
            ft_putstr_fd(1, "\n", 1);
        } else if (arg == NULL) {
            if (IS_SET(flags, FLAG_P)) {
                ft_putstr_fd(1, digest, ctx->digest_size * 2);
            } else {
                ft_putstr_fd(1, "(stdin) = ", 10);
            }
            ft_putstr_fd(1, "\n", 1);
        } else {
            ft_putstr_fd(1, ctx->alg_name, ft_strlen(ctx->alg_name));
            ft_putstr_fd(1, " (\"", 3);
            ft_putstr_fd(1, arg, ft_strlen(arg));
            ft_putstr_fd(1, "\"", 1);
            ft_putstr_fd(1, ") = ", 4);
            ft_putstr_fd(1, digest, ctx->digest_size * 2);
            ft_putstr_fd(1, "\n", 1);
        }
    }
}
