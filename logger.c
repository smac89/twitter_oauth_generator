#include <stdarg.h>
#include <stdio.h>
#include "logger.h"

void o_log(const char *message, ...) {
    va_list args;
    va_start (args, message);
    (void) vprintf(message, args);
    va_end(args);
}

void e_log(const char *message, ...) {
    va_list args;
    va_start (args, message);
    (void) vfprintf(stderr, message, args);
    va_end(args);
}

void f_log(FILE *out, const char *message, ...) {
    va_list args;
    va_start (args, message);
    (void) vfprintf(out, message, args);
    va_end(args);
}
