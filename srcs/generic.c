#include "ft_ssl.h"

/**
 * @brief Copies BUFFER_SIZE bytes from the buffer to internal buffer
 * 
 * @note Can mark the context as finalized if n < BUFFER_SIZE or if the known size is reached
 * 
 * @param ctx Hash context
 * @param buf A not-sentinel-terminated buffer
 * @param n Number of bytes to eat (if > BUFFER_SIZE, the rest is dropped)
 */
void ctx_chomp(t_context *ctx, const byte *buf, u64 n) {
    memcpy(ctx->buffer, buf, n);
    ctx->buffer_size = n;
    if (n < BUFFER_SIZE || (ctx->known_size != 0 && ctx->known_size == ctx->chomped_bytes + ctx->buffer_size)) {
        ctx_finish(ctx);
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
    if (IS_SET(flags, FLAG_Q) || IS_SET(flags, FLAG_P)) {
        printf("%s\n", digest);
        return ;
    }
    if (IS_SET(flags, FLAG_R)) {
        if (is_file) {
            printf("%s %s\n", digest, arg);
        } else {
            printf("%s \"%s\"\n", digest, arg);
        }
        return ;
    } else {
        if (is_file) {
            printf("%s(%s)= %s\n", ctx->alg_name, arg, digest);
        } else if (arg == NULL) {
            printf("%s(stdin)= %s\n", ctx->alg_name, digest);
        } else {
            printf("%s(\"%s\")= %s\n", ctx->alg_name, arg, digest);
        }
    }
}
