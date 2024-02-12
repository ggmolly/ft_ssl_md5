#include "ft_ssl.h"

/**
 * @brief Returns a new context for the SHA256 hash function
 * 
 * @note Initialize the digest to :
 * UNK
 * 
 * @param known_size Size of the message to hash, 0 if unknown
 * 
 * @return t_context Freshly created context
 */
t_context sha256_init(u64 known_size) {
    t_context new_ctx;
    new_ctx.chomped_bytes = 0;
    new_ctx.chomp_fn = NULL;
    new_ctx.final_fn = NULL;
    new_ctx.digest_size = SHA256_DIGEST_SIZE * 4;
    new_ctx.known_size = known_size;
    //memcpy(new_ctx.digest, _md5_initial_digest, MD5_DIGEST_SIZE * 4);   
    return new_ctx;
}
