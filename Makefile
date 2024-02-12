CC := gcc
INCLUDE_FLAGS := -I includes/
CFLAGS := ${INCLUDE_FLAGS} -MMD -g3 -Wall -Wextra -Werror -O0 -fsanitize=address -fsanitize=undefined -fsanitize=leak -fsanitize=pointer-subtract -fsanitize=pointer-compare -fsanitize=pointer-overflow # -O2 -march=native -pipe
NAME = ft_ssl
SRCS = srcs/main.c \
		srcs/bit_manip.c \
		srcs/md5.c \
		srcs/context.c \

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

.c:.o
	${CC} $(CFLAGS) -c $< -o $@

$(NAME): $(OBJS) Makefile
	${CC} $(CFLAGS) -o $(NAME) $(OBJS) -lm

clean:
	rm -f $(OBJS) $(DEPS)

fclean: clean
	rm -f $(NAME)

re: fclean all

all: $(NAME)


-include $(DEPS)
leak-test: all
	valgrind --leak-check=full --show-below-main=yes --show-leak-kinds=all ./$(NAME)

scan-build: fclean clean
	scan-build-12 make | grep "^scan-build:"

.PHONY: all clean fclean re scan-build pre-push