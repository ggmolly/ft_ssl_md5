#include "ft_ssl.h"

// https://en.wikipedia.org/wiki/MD5

static const u32 _md5_initial_digest[MD5_DIGEST_SIZE / 4] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
};

// s specifies the per-round shift amounts
static const u32 s[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

// Pre-computed radians (to avoid using costly trigonometric functions)
static const u32 k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/**
 * @brief Eats BUFFER_SIZE bytes from the buffer and updates the hash context
 * 
 * @param ctx Hash context
 * @param buf A sentinel-terminated buffer
 * @param n Number of bytes to eat (if > BUFFER_SIZE, the rest is dropped)
 */
void md5_digest(t_context *ctx) {
    // process 512-bit chunks (512 / 8 = 64)
    u32 dwords[16];
    u32 h0, h1, h2, h3, f, g, pivot, a, b, c, d;

    // digest is a unsigned char array, h0..3 are 32-bit integers
    // for each var, fetch 4 bytes from the digest and convert them to a 32-bit integer
    h0 = to_u32(ctx->digest);
    h1 = to_u32(ctx->digest + 4);
    h2 = to_u32(ctx->digest + 8);
    h3 = to_u32(ctx->digest + 12);
    for (u32 offset = 0; offset < ctx->buffer_size; offset += 64) {
        // break into 16 32-bit dwords
        for (i32 i = 0; i < 16; i++) {
            dwords[i] = to_u32((ctx->buffer + offset) + i * 4);
        }

        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // main loop
        for (i32 i = 0; i < 64; i++) {
            if (i < 16) {
                // F
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                // G
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                // H
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                // I
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }

            pivot = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + dwords[g]), s[i]);
            a = pivot;
        }

        // add this chunk's hash to result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }
    // store the result in the digest
    to_bytes(h0, ctx->digest);
    to_bytes(h1, ctx->digest + 4);
    to_bytes(h2, ctx->digest + 8);
    to_bytes(h3, ctx->digest + 12);
    ctx->chomped_bytes += ctx->buffer_size;
}

/**
 * @brief Finalize the MD5 hash function, runs post-processing steps
 * 
 * @note MD5 post-processing steps:
 * 1. Append a 1 bit to the message
 * 2. Append the length of the message to the message
 * 3. Pad the message with "0" bits until the length is congruent to 448 (mod 512)
 * 
 * @param ctx Hash context
 */
void md5_final(t_context *ctx) {
    // append 1-bit
    u32 initial_length = ctx->chomped_bytes + ctx->buffer_size;
    ctx->buffer[ctx->buffer_size++] = 0b10000000;
    u32 msg_length = ctx->buffer_size;
    // pad with 0s to make the message congruent to 448 (mod 512)
    while (msg_length % 64 != 56) {
        ctx->buffer[ctx->buffer_size] = 0b00000000;
        msg_length++;
        ctx->buffer_size++;
    }
    // append length
    to_bytes(initial_length << 3, ctx->buffer + ctx->buffer_size);
    to_bytes(initial_length >> (32-3), ctx->buffer + ctx->buffer_size + 4);
    ctx->buffer_size += 8;
}

/**
 * @brief Resets the context to its initial state
 * 
 * @param ctx Hash context
 */
void md5_reset(t_context *ctx) {
    ctx->chomped_bytes = 0;
    ctx->stream_finished = false;
    ctx->buffer_size = 0;
    ft_memcpy(ctx->digest, _md5_initial_digest, MD5_DIGEST_SIZE * 4);
}

/**
 * @brief Returns a new context for the MD5 hash function
 * 
 * @note Initialize the digest to :
 * 0x67452301efcdab8998badcfe10325476;
 * 
 * @param known_size Size of the message to hash, 0 if unknown
 * 
 * @return t_context Freshly created context
 */
t_context md5_init(u64 known_size) {
    t_context new_ctx;
    new_ctx.chomped_bytes = 0;
    new_ctx.digest_fn = md5_digest;
    new_ctx.final_fn = md5_final;
    new_ctx.reset_fn = md5_reset;
    new_ctx.digest_size = MD5_DIGEST_SIZE;
    new_ctx.known_size = known_size;
    new_ctx.stream_finished = false;
    new_ctx.alg_name = MD5_ALG_NAME;
    new_ctx.block_size = MD5_BLOCK_SIZE;
    ft_memcpy(new_ctx.digest, _md5_initial_digest, MD5_DIGEST_SIZE * 4);   
    return new_ctx;
}