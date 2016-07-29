#include <logger.h>
#include <stdarg.h>
#include <stdio.h>

void o_log(const char *message, ...) {
    va_list args;
    va_start(args, message);
    ( void )vprintf(message, args);
    puts("");
    va_end(args);
}

void e_log(const char *message, ...) {
    va_list args;
    va_start(args, message);
    ( void )vfprintf(stderr, message, args);
    fputs("", stderr);
    va_end(args);
}

void f_log(FILE *out, const char *message, ...) {
    va_list args;
    va_start(args, message);
    ( void )vfprintf(out, message, args);
    fputs("", out);
    va_end(args);
}
