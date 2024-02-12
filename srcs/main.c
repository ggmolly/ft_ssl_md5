#include "ft_ssl.h"

int main(int argc, char **argv) {
    if (argc != 2) { return (1); }
    i32 len = strlen(argv[1]);

    t_context ctx = md5_init(len);

    for (i32 i = 0; i < len; i += BUFFER_SIZE) {
        i32 buffer_length = len - i;
        if (buffer_length > BUFFER_SIZE) {
            buffer_length = BUFFER_SIZE;
        }
        ctx.chomp_fn(&ctx, (byte *)argv[1] + i, buffer_length);
    }
    if (len % BUFFER_SIZE == 0) {
        ctx.buffer_size = 0;
        ctx.final_fn(&ctx);
    }

    for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
        printf("%02x", ctx.digest[i]);
    }
    return 0;
}
