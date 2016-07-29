#ifndef OAUTH_LOGGER
#define OAUTH_LOGGER

//#include <string.h>
//#define __FILENAME__ ((strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__))
//
//#define O_LOG(msg, ...) o_log("[ "__FILENAME__" ] "msg, __VA_ARGS__)
//##"::"##__FUNCTION__##":"__LINE__##"

/**
 * @brief      Logs some message to standard output
 *
 * @param[in]  message    The message can also include format specifiers
 * @param[in]  <unnamed>  format arguements
 */
void o_log(const char *message, ...);

/**
 * @brief      Logs some message to standard error
 *
 * @param[in]  message    The message can also include format specifiers
 * @param[in]  <unnamed>  format arguements
 */
void e_log(const char *message, ...);

/**
 * @brief      Logs the message to a file specified by the user
 *
 * @param      out        The file where the log will be stored
 * @param[in]  message    The message to write. It can also include format specifiers
 * @param[in]  <unnamed>  format specifier arguments
 */
void f_log(FILE *out, const char *message, ...);

#endif
