#include "ft_ssl.h"

// https://en.wikipedia.org/wiki/SHA-2

static const u32 _sha256_initial_digest[SHA256_DIGEST_SIZE / 4] = {
    0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
};

static const u32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * @brief Eats BUFFER_SIZE bytes from the buffer and updates the hash context
 * 
 * @param ctx Hash context
 * @param buf A sentinel-terminated buffer
 * @param n Number of bytes to eat (if > BUFFER_SIZE, the rest is dropped)
 */
void sha256_digest(t_context *ctx) {
    // process 512-bit chunks (512 / 8 = 64)
    u32 words[64];
    u32 h0, h1, h2, h3, h4, h5, h6, h7, s0, s1, ch, maj, temp1, temp2, a, b, c, d, e, f, g, h;

    // digest is a unsigned char array, h0..7 are 32-bit integers
    // for each var, fetch 4 bytes from the digest and convert them to a 32-bit integer
    h0 = to_u32(ctx->digest);
    h1 = to_u32(ctx->digest + 4);
    h2 = to_u32(ctx->digest + 8);
    h3 = to_u32(ctx->digest + 12);
    h4 = to_u32(ctx->digest + 16);
    h5 = to_u32(ctx->digest + 20);
    h6 = to_u32(ctx->digest + 24);
    h7 = to_u32(ctx->digest + 28);

    for (u32 offset = 0; offset < ctx->buffer_size; offset += 64) {
        for (i32 i = 0; i < 64; i++) {
        }
        // break into 16 32-bit words
        for (i32 i = 0; i < 16; i++) {
            words[i] = to_u32(ctx->buffer + offset + i * 4);
            // swap endianness (little to big endian)
            words[i] = (words[i] >> 24) | ((words[i] >> 8) & 0xFF00) | ((words[i] << 8) & 0xFF0000) | (words[i] << 24);
        }

        // extend the 16 words into 64 words
        for (i32 i = 16; i < 64; i++) {
            s0 = RIGHTROTATE(words[i-15], 7) ^ RIGHTROTATE(words[i-15], 18) ^ (words[i-15] >> 3);
            s1 = RIGHTROTATE(words[i-2], 17) ^ RIGHTROTATE(words[i-2], 19) ^ (words[i-2] >> 10);
            words[i] = words[i-16] + s0 + words[i-7] + s1;
        }

        // initialize working variables
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        // main loop
        for (i32 i = 0; i < 64; i++) {
            s1 = RIGHTROTATE(e, 6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = h + s1 + ch + k[i] + words[i];
            s0 = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // add this chunk's hash to result so far
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;

    }
    // store the result in the digest
    to_bytes(h0, ctx->digest);
    to_bytes(h1, ctx->digest + 4);
    to_bytes(h2, ctx->digest + 8);
    to_bytes(h3, ctx->digest + 12);
    to_bytes(h4, ctx->digest + 16);
    to_bytes(h5, ctx->digest + 20);
    to_bytes(h6, ctx->digest + 24);
    to_bytes(h7, ctx->digest + 28);
}

/**
 * @brief Finalize the SHA-256 hash function, runs post-processing steps
 * 
 * @note SHA-256 post-processing steps:
 * - Append a single '1' bit to the message
 * - Append K '0' bits, where K is the minimum number >= 0 such that the resulting message length in bits is a multiple of 512 bits (64 bytes)
 * - Append L as a 64-bit big-endian integer, where L is the length of the original message, a multiple of 512 bits (64 bytes)
 * 
 * @param ctx Hash context
 */
void sha256_final(t_context *ctx) {
    // append 1-bit
    u64 bits = (ctx->chomped_bytes) * 8;
    ctx->buffer[ctx->buffer_size++] = 0b10000000;

    // append '0' bits until the total length is 448 mod 512
    while (ctx->buffer_size % 64 != 56) {
        ctx->buffer[ctx->buffer_size++] = 0;
    }

    // append 64-bit length of the original message
    for (int i = 0; i < 8; i++) {
        ctx->buffer[ctx->buffer_size++] = (bits >> (56 - i * 8)) & 0xFF;
    }
    ctx->digest_fn(ctx);

    // swap endianness of digest
    for (i32 i = 0; i < 8; i++) {
        u32 tmp = to_u32(ctx->digest + i * 4);
        to_bytes((tmp >> 24) | ((tmp >> 8) & 0xFF00) | ((tmp << 8) & 0xFF0000) | (tmp << 24), ctx->digest + i * 4);
    }

}


/**
 * @brief Resets the context to its initial state
 * 
 * @param ctx Hash context
 */
void sha256_reset(t_context *ctx) {
    ctx->chomped_bytes = 0;
    ctx->stream_finished = false;
    ctx->buffer_size = 0;
    ft_memcpy(ctx->digest, _sha256_initial_digest, SHA256_DIGEST_SIZE);
}

/**
 * @brief Returns a new context for the SHA256 hash function
 * 
 * @note Initialize the digest to :
 * 0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19
 * 
 * @param known_size Size of the message to hash, 0 if unknown
 * 
 * @return t_context Freshly created context
 */
t_context sha256_init(u64 known_size) {
    t_context new_ctx;
    new_ctx.chomped_bytes = 0;
    new_ctx.digest_fn = sha256_digest;
    new_ctx.final_fn = sha256_final;
    new_ctx.reset_fn = sha256_reset;
    new_ctx.digest_size = SHA256_DIGEST_SIZE;
    new_ctx.buffer_size = 0;
    new_ctx.stream_finished = false;
    new_ctx.alg_name = SHA256_ALG_NAME;
    new_ctx.known_size = known_size;
    ft_memcpy(new_ctx.digest, _sha256_initial_digest, SHA256_DIGEST_SIZE);
    return new_ctx;
}
