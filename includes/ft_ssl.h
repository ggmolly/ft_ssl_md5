#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "short_types.h"

// Errors
#define ERR_MEM_ALLOC_FAILED "failed to allocate memory"
#define ERR_ALG_SPECIFIED_TWICE "algorithm specified twice"
#define ERR_ALG_NOT_FOUND "algorithm not found"
#define ERR_INVALID_FLAG "invalid flag"
#define ERR_DUPLICATE_FLAG "flag specified twice"
#define ERR_FILE_NOT_FOUND "file not found"
#define ERR_FILE_READ_FAILED "failed to read file"

// Crypto constants
#define MAX_DIGEST_SIZE 32 // SHA-256
#define BUFFER_SIZE 16384 // will chomp 16384 bytes at a time

// Helper macros
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
#define IS_SET(flags, flag) ((flags & flag) == flag)
#define SET_FLAG(flags, flag) (flags |= flag)
#define UNSET_FLAG(flags, flag) (flags &= ~flag)

// Flags
#define FLAG_P          0b00000001
#define FLAG_Q          0b00000010
#define FLAG_R          0b00000100
#define FLAG_S          0b00001000
#define FLAG_ALG_MD5    0b10000000
#define FLAG_ALG_SHA256 0b01000000

// forward declaration
struct s_context;

typedef void (*digest_func)(struct s_context *ctx);
typedef void (*final_func)(struct s_context *ctx);
typedef void (*reset_func)(struct s_context *ctx);

/*
    A context is a structure that holds the state of the hash function.
    - Chomped bytes (meaning the bytes that have been processed)
    - Initialization bytes (the initial bytes that are used to initialize the hash function)
    - The digest function itself
    - The finalization function
    - The digest (the final hash value)
    - The size of the digest (MD5 is 16 bqytes long, SHA-256 is 32 bytes long)
    - The buffer (the buffer that holds the input)
*/

typedef struct s_context {
    u64 chomped_bytes;                  // The number of bytes that have been processed
    digest_func digest_fn;              // The function that consumes N bytes of the internal buffer
    final_func final_fn;                // The finalization function
    reset_func reset_fn;                // The reset function
    byte digest[MAX_DIGEST_SIZE * 4];   // The final hash value -> will be initialized depending on the hash function
    u8 digest_size;                     // The size of the digest, we have to know it to not overflow the digest buffer :^)
    byte buffer[BUFFER_SIZE+128];       // The buffer that holds the input + space for padding
    u16 buffer_size;                    // Number of bytes in the buffer
    u64 known_size;                     // Total size of the input, 0 if unknown
    bool stream_finished;               // True if the stream has been finished (no more input)
    char *alg_name;                     // The name of the algorithm
} t_context;

// Bit utils functions
void to_bytes(u32 n, byte *output);
u32 to_u32(const byte *bytes);

// Generic functions / stuff
void ctx_chomp(t_context *ctx, const byte *buf, u64 n);
void ctx_finish(t_context *ctx);
void ctx_hexdigest(t_context *ctx, unsigned char *out);
void ctx_print_digest(t_context *ctx, char *arg, bool is_file, u8 flags);

// hehe funny ft functions :^)
i32 ft_strlen(const char *s);
i32 ft_strncmp(const char *s1, const char *s2, u64 n);
void *ft_memcpy(void *dest, const void *src, u64 n);

// Argument parsing
i32 parse_parameters(int argc, char **argv, u8* flags);

// Error management
void print_error(const char *error_message, char *details);

// MD5 functions / stuff
#define MD5_DIGEST_SIZE 16
#define MD5_ALG_NAME "MD5"
#define MD5_BLOCK_SIZE 64

t_context md5_init(u64 known_size);
void md5_final(t_context *ctx);
void md5(const byte *initial_msg, size_t initial_len, byte *digest);

// SHA-256 functions / stuff
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define SHA256_ALG_NAME "SHA256"

t_context sha256_init(u64 known_size);