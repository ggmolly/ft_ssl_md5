#include "short_types.h"
#include <unistd.h>

i32 ft_strlen(const char *s) {
    i32 i = 0;
    while (s[i] != 0x00) {
        i++;
    }
    return (i);
}

i32 ft_strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (*(u8 *)s1 - *(u8 *)s2);
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