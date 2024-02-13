#include "short_types.h"

/**
 * I wont do inline asm for SIMD, but I like to use bitwise tricks
*/

i32 ft_strlen(const char *s) {
    const char *char_ptr;
    const u64 *multibyte_ptr;

    // Align the pointer to 8 bytes
    for (char_ptr = s; ((u64)char_ptr & 7) != 0; ++char_ptr) {
        if (*char_ptr == '\0') {
            return (char_ptr - s);
        }
    }
    u64 high_magic = 0x80808080L;
    u64 low_magic  = 0x01010101L;
    multibyte_ptr = (const u64 *)char_ptr;

    if (sizeof(u64) > 4) { // 64-bit version, check 8 bytes at a time
        high_magic = (high_magic << 32) | high_magic;
        low_magic  = (low_magic << 32) | low_magic;
    }
    for (;;) {
        u64 data = *multibyte_ptr++; // load 8 bytes (or 4 bytes if 32-bit version)
        if (((data - low_magic) & ~data & high_magic) != 0) { // check if any byte is 0
            const char *cp = (const char *)(multibyte_ptr - 1); // get the pointer to the 8 bytes
            if (cp[0] == 0) return (cp - s);        // a 0 ? oh maybe in the 1st byte
            if (cp[1] == 0) return (cp - s + 1);    // a 0 ? oh maybe in the 2nd byte
            if (cp[2] == 0) return (cp - s + 2);    // a 0 ? oh maybe in the 3rd byte
            if (cp[3] == 0) return (cp - s + 3);    // a 0 ? oh maybe in the 4th byte
            if (sizeof(u64) > 4) {
                if (cp[4] == 0) return (cp - s + 4); // a 0 ? oh maybe in the 5th byte
                if (cp[5] == 0) return (cp - s + 5); // a 0 ? oh maybe in the 6th byte
                if (cp[6] == 0) return (cp - s + 6); // a 0 ? oh maybe in the 7th byte
                if (cp[7] == 0) return (cp - s + 7); // a 0 ? oh maybe in the 8th byte
            }
        }
    }
    return (0); // should never reach this point
}

// glibc has an interesting 4x unrolled version of this function
// but it's not very interesting
i32 ft_strncmp(const char *s1, const char *s2, u64 n) {
    while (n > 0 && *s1 != 0x00 && *s1 == *s2) {
        n--;
        s1++;
        s2++;
    }
    return (n == 0 ? 0 : *(unsigned char *)s1 - *(unsigned char *)s2);
}

// glibc's memcpy has a multi-byte copy, but same as strncmp, it's not very interesting
void *ft_memcpy(void *dest, const void *src, u64 n) {
    char *d = dest;
    const char *s = src;
    while (n-- > 0) {
        *d++ = *s++;
    }
    return (dest);
}