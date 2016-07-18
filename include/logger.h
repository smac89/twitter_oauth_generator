#ifndef OAUTH_LOGGER
#define OAUTH_LOGGER

void o_log(const char *message, ...);

void e_log(const char *message, ...);

void f_log(FILE *out, const char *message, ...);

#endif