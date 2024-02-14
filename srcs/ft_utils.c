#include "short_types.h"
#include <unistd.h>

i32 ft_strlen(const char *s) {
    i32 i = 0;
    while (s[i] != 0x00) {
        i++;
    }
    return (i);
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

i64 ft_putstr_fd(i32 fd, const void *s, i64 len) {
    return write(fd, (const char *)s, len);
}