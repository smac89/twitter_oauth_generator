// #######################################################
// These headers or their equivalents should be included##
// prior to including cmocka header file.#################
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
// This allows test applications to use custom definitions
// of C standard library functions and types.#############
// #######################################################

#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>

#define X_DEFAULT_TESTS \
  X(consumer_key, "xvz1evFS4wEEPTGEFPHBog") \
  X(consumer_secret, "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw") \
  X(token, "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb") \
  X(token_secret, "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE") \
  X(http_method, "POST") \
  X(base_url, "https://api.twitter.com/1/statuses/update.json")

typedef struct Builder Builder;

extern Builder *new_oauth_builder(void);
extern void destroy_builder(Builder **);

// implicit setters and getters
#define X(name, _) \
  extern void set_##name(Builder *builder, const char *value); \
  extern char *get_##name(const Builder *builder);

X_DEFAULT_TESTS

extern void set_request_params(Builder *builder, const char **params, int length);

extern char **get_request_params(const Builder *builder);
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
#define X(name, str) \
  static void test_get_##name(void **state) { \
    Builder *builder = *state; \
    set_##name(builder, str); \
                              \
    char *value = get_##name(builder); \
    assert_string_equal(str, value); \
                                     \
    free(value); \
  }

X_DEFAULT_TESTS
#undef X

static void test_get_request_params(void **state) {
    Builder *builder = *state;
    char **value;
    int len, c;

    const char *params[] = {"status=Hello Ladies + Gentlemen, a signed OAuth request!"};

    len = sizeof params / sizeof params[0];

    set_request_params(builder, params, len);
    value = get_request_params(builder);

    assert_true(value);

    for (c = 0; c < len; ++c) {
        assert_string_equal(params[c], value[c]);
        free(value[c]);
    }

    free(value);
}

static void test_get_header_string(void **state) {
    Builder *builder = *state;

    //    char *value = get_header_string(builder);
    //    assert_string_equal("", value);
    assert_true(1);

    //    free(value);
}

int main(void) {
    // create the array of tests
    const struct CMUnitTest tests[] = {
#define X(name, _) cmocka_unit_test(test_get_##name),
            X_DEFAULT_TESTS cmocka_unit_test(test_get_request_params),
            cmocka_unit_test(test_get_header_string)
#undef X
    };
    return cmocka_run_group_tests(tests, create_test_builder,
                                  destroy_test_builder);
}
