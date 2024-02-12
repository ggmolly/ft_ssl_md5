#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "short_types.h"

#define ERR_MEM_ALLOC_FAILED "failed to allocate memory"

// Helper macros
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#define MAX_DIGEST_SIZE 32 // SHA-256
#define BUFFER_SIZE 4096 // will chomp 4096 bytes at a time

// forward declaration
struct s_context;

typedef void (*chomp_func)(struct s_context *ctx, const byte *input, u64 size);
typedef void (*final_func)(struct s_context *ctx);

/*
    A context is a structure that holds the state of the hash function.
    - Chomped bytes (meaning the bytes that have been processed)
    - Initialization bytes (the initial bytes that are used to initialize the hash function)
    - The chomp function itself
    - The finalization function
    - The digest (the final hash value)
    - The size of the digest (MD5 is 16 bqytes long, SHA-256 is 32 bytes long)
    - The buffer (the buffer that holds the input)
*/

typedef struct s_context {
    u64 chomped_bytes;                  // The number of bytes that have been processed
    chomp_func chomp_fn;                // The function that consumes N bytes of the input
    final_func final_fn;                // The finalization function
    byte digest[MAX_DIGEST_SIZE * 4];   // The final hash value -> will be initialized depending on the hash function
    u8 digest_size;                     // The size of the digest, we have to know it to not overflow the digest buffer :^)
    byte buffer[BUFFER_SIZE+128];       // The buffer that holds the input + space for padding
    u16 buffer_size;                    // Number of bytes in the buffer
    u64 known_size;                     // Total size of the input, 0 if unknown
} t_context;

// Bit utils functions
void to_bytes(u32 n, byte *output);
u32 to_u32(const byte *bytes);

// MD5 functions / stuff

#define MD5_DIGEST_SIZE 16

t_context md5_init(u64 known_size);
void md5_final(t_context *ctx);
void md5(const byte *initial_msg, size_t initial_len, byte *digest);