#include "ft_ssl.h"
#include <unistd.h>

/**
 * @brief Prints an error message to stderr, with arguments
 *
*/
void print_error(const char *error_message, char *details) {
    ft_putstr_fd(2, "ft_ssl: ", 8);
    ft_putstr_fd(2, error_message, ft_strlen(error_message));
    if (details != NULL) {
        ft_putstr_fd(2, ": '", 3);
        ft_putstr_fd(2, details, ft_strlen(details));
    }
    ft_putstr_fd(2, "'\n", 2);
}