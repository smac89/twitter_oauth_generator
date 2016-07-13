#include <stdarg.h>
#include <stdio.h>
#include <sysexits.h>
#include "logger.h"

// for testing purposes
// int main(int argc, char *argv[]) {
//     o_log("This should show zero: %d\n", 0);
//     e_log("This should show one: %d\n", 1);
//     if (argc > 1) {
//         FILE* f = fopen(argv[1], "w");
//         if (f != NULL) {
//             f_log(f, "This should show three: %d\n", 3);
//             fclose(f);
//         } else {
//             return EX_OSFILE;
//         }
//     }
//     return EX_OK;
// }

void o_log( const char* message, ... ) {
    va_list args;
    va_start (args, message);
    (void) vprintf(message, args);
    va_end( args );
}

void e_log( const char* message, ... ) {
    va_list args;
    va_start (args, message);
    (void) vfprintf(stderr, message, args);
    va_end( args );
}

void f_log( FILE* out, const char* message, ...) {
    va_list args;
    va_start (args, message);
    (void) vfprintf(out, message, args);
    va_end( args );
}
