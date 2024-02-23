#include "ft_ssl.h"

/**
 * @brief Parse the argument in the command line, and set the flags accordingly.
 * 
 * @param arg Argument to parse
 * @param flags Format bitmask
 * @return true Argument was parsed successfully
 * @return false An error occurred
 */
bool parse_arg(char *arg, u8 *flags) {
    u8 before = *flags;
    switch (arg[1])
    {
        case 'p':
            SET_FLAG(*flags, FLAG_P);
            break;
        case 'q':
            SET_FLAG(*flags, FLAG_Q);
            break;
        case 'r':
            SET_FLAG(*flags, FLAG_R);
            break;
        case 's':
            SET_FLAG(*flags, FLAG_S);
            break;
        default:
            print_error(ERR_INVALID_FLAG, arg);
            return (false);
            break;
    }
    if (before == *flags && arg[1] != 's') {
        print_error(ERR_DUPLICATE_FLAG, arg);
        return (false);
    }
    return (true);
}

/**
 * @brief Sets the flags from the command line arguments
 * 
 * @param argc Number of arguments
 * @param argv All passed arguments
 * @param flags Pointer to the flags bitmask
 * @return i32 Number of parameters parsed
 */
i32 parse_parameters(int argc, char **argv, u8* flags) {
    i32 parameters = 0;
    for (i32 i = 2; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!parse_arg(argv[i], flags)) {
                return (-1);
            } else if (argv[i][1] == 's') {
                break;
            }
            parameters++;
        } else { // non-flag argument, stop parsing flags
            break;
        }
    }
    return parameters;
}