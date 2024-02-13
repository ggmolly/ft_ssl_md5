#include "ft_ssl.h"
#include <unistd.h>

/**
 * @brief Prints an error message to stderr, with arguments
 *
*/
void print_error(const char *error_message, char *details) {
    write(2, "ft_ssl: ", 8);
    write(2, error_message, ft_strlen(error_message));
    if (details != NULL) {
        write(2, ": '", 3);
        write(2, details, ft_strlen(details));
    }
    write(2, "'\n", 2);
}