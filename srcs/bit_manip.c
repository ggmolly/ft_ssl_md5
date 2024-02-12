#include "ft_ssl.h"

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