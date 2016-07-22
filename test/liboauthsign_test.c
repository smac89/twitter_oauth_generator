// #######################################################
// These headers or their equivalents should be included##
// prior to including cmocka header file.#################
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
// This allows test applications to use custom definitions
// of C standard library functions and types.#############
// #######################################################

#include <cmocka.h>
#include <stdlib.h>

#define X_DEFAULT_TESTS \
X(consumer_key) \
X(consumer_secret) \
X(token) \
X(token_secret) \
X(http_method) \
X(base_url) \
X(request_params)

typedef struct Builder Builder;

extern Builder *new_oauth_builder(void);

extern void destroy_builder(Builder **);

// implicit setters and getters
#define X(name) \
extern void set_##name(Builder *builder, const char *value); \
extern char *get_##name(const Builder *builder);

X_DEFAULT_TESTS

extern char *get_header_string(Builder *builder);

#undef X

/**
 * @brief      Creates a group test builder.
 *
 * @param      state  The state
 *
 * @return     Success
 */
static int
create_test_builder(void **state) {
    Builder *b = new_oauth_builder();
    *state = b;
    return 0;
}

/**
 * @brief      Destroys the group test builder
 *
 * @param      state  The state
 *
 * @return     Success if the builder was successfully destroyed
 */
static int
destroy_test_builder(void **state) {
    Builder *b = *state;
    test_free(*state);
    destroy_builder(&b);

    return b == NULL ? 0 : -1;
}

// generate tests
#define X(name) static void test_get_##name(void **state) { \
    Builder *builder = *state; \
    set_##name(builder, ""); \
    \
    char *value = get_##name(builder); \
    assert_string_equal("", value); \
    \
    free(value); \
}

X_DEFAULT_TESTS

#undef X

static void test_get_header_string(void **state) {
    Builder *builder = *state;

    char *value = get_header_string(builder);
    assert_string_equal("", value);

    free(value);
}

int main(void) {
    // create the array of tests
    const struct CMUnitTest tests[] = {
#define X(name) cmocka_unit_test(test_get_##name),
            X_DEFAULT_TESTS
#undef X
            cmocka_unit_test(test_get_header_string)
    };
    return cmocka_run_group_tests(tests, create_test_builder, destroy_test_builder);
}
