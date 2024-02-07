#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "short_types.h"

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define ERR_MEM_ALLOC_FAILED "failed to allocate memory"

// https://en.wikipedia.org/wiki/MD5

// s specifies the per-round shift amounts
u32 s[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

// Pre-computed radians (to avoid using costly trigonometric functions)
u32 k[] = {
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
 * @brief Convert a 32-bit unsigned integer to a little endian byte array
 * 
 * @param n The 32-bit unsigned integer
 * @param output Pointer to a byte array of size 4
 */
void to_bytes(u32 n, byte *output) {
    output[0] = (byte) n;
    output[1] = (byte) (n >> 8);
    output[2] = (byte) (n >> 16);
    output[3] = (byte) (n >> 24);
}

/**
 * @brief Convert a little endian byte array to a 32-bit unsigned integer
 * 
 * @param bytes Pointer to a byte array of size 4
 * @return u32 The 32-bit unsigned integer
 */
u32 to_u32(const byte *bytes) {
    return (u32) bytes[0] | ((u32) bytes[1] << 8) | ((u32) bytes[2] << 16) | ((u32) bytes[3] << 24);
}

/**
 * @brief MD5 hash function, takes a message and its length and writes the hash to the digest pointer
 * 
 * @param initial_msg Pointer to the message
 * @param initial_len Length of the message
 * @param digest Output pointer to the digest
 */
void md5(const byte *initial_msg, size_t initial_len, byte *digest) {
    // Initialize h0..3, these are the starting values of the four registers
    u32 h0 = 0x67452301;
    u32 h1 = 0xefcdab89;
    u32 h2 = 0x98badcfe;
    u32 h3 = 0x10325476;

    // Message (to prepare)
    byte *msg = NULL;

    size_t new_len, offset;
    u32 dwords[16]; // DWORDS are 32-bit integers (or 4 bytes)
    u32 a, b, c, d, i, f, g, temp;

    // Pre-processing: append "1" bit to the message
    // and append "0" bits until the resulting length is congruent to 448 (mod 512)
    // so we can properly process the message in 512-bit chunks without leftover bits
    new_len = initial_len + 1; // +1 for the "1" bit we append
    while (new_len % (512 / 8) != 448/8) {
        ++new_len; // +1 for each "0" bit we append
    }

    // Reallocate memory for the new message to pad/append bits
    msg = (byte*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0b10000000; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0b00000000; // append "0" bits

    // append the len in bits at the end of the buffer.
    // the shift by 3 is used to
    to_bytes(initial_len << 3, msg + new_len);

    // shift right to get the high 32 bits
    to_bytes(initial_len >> (32-3), msg + new_len + 4);

    // Process the message in successive 512-bit chunks:
    for(offset = 0; offset < new_len; offset += (512 / 8)) {
        // break chunk into sixteen 32-bit dwords words[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            dwords[i] = to_u32(msg + offset + i*4);

        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // Main loop:
        for(i = 0; i<64; i++) {
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + dwords[g]), s[i]);
            a = temp;
        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    // cleanup
    free(msg);

    // var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

int main(int argc, char **argv) {
    char *msg = "hello world";
    size_t len = strlen(msg);
    byte digest[16];

    md5(msg, len, digest);

    int i;
    for(i = 0; i < 16; i++)
        printf("%2x", digest[i]);
    puts("");

    return 0;
}
