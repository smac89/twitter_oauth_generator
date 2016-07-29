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
  X(base_url, "https://api.twitter.com/1/statuses/update.json") \
  X(nonce, "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg") \
  X(signature_method, "HMAC-SHA1") \
  X(timestamp, "1318622958") \
  X(oauth_version, "1.0")

typedef struct mBuilder Builder;

extern Builder *new_oauth_builder(void);
extern void destroy_builder(Builder **);

// implicit setters and getters
#define X(name, _) \
  extern void set_##name(Builder *builder, const char *value); \
  extern char *get_##name(const Builder *builder);

X_DEFAULT_TESTS

extern void set_request_params(Builder *builder, const char **params, int length);
extern char **get_request_params(const Builder *builder);
extern char *get_authorization_header(Builder *builder);
extern char *get_cURL_command(Builder *builder);
extern char *get_signature_base(Builder *builder);

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

    const char *params[] = {
            "include_entities=true",
            "status=Hello Ladies + Gentlemen, a signed OAuth request!"
    };

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

static void test_get_signature_base(void **state) {
    Builder *builder = *state;

    char *base = get_signature_base(builder);

    assert_string_equal("POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&"
                                "include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog"
                        "%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method"
                        "%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token"
                        "%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0"
                        "%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed"
                        "%2520OAuth%2520request%2521", base);

    free(base);
}

static void test_get_header_string(void **state) {
    Builder *builder = *state;

    char *value = get_authorization_header(builder);

    assert_string_equal("OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", "
                                "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", "
                                "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", "
                                "oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", "
                                "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", "
                                "oauth_version=\"1.0\"", value);
    free(value);
}

static void test_get_cURL_command(void **state) {
    Builder *builder = *state;

    char *value = get_cURL_command(builder);
    assert_string_equal("curl --request 'POST' 'https://api.twitter.com/1/statuses/update.json' "
                                "--data 'include_entities=true&status=Hello Ladies + Gentlemen, a signed OAuth request!' "
                                "--header 'Authorization: OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", "
                                "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", "
                                "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", "
                                "oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", "
                                "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", "
                                "oauth_version=\"1.0\"' --verbose", value);
    free(value);
}

int main(void) {
    // create the array of tests
    const struct CMUnitTest tests[] = {
#define X(name, _) cmocka_unit_test(test_get_##name),
            X_DEFAULT_TESTS
            cmocka_unit_test(test_get_request_params),
            cmocka_unit_test(test_get_header_string),
            cmocka_unit_test(test_get_cURL_command),
            cmocka_unit_test(test_get_signature_base)
#undef X
    };
    return cmocka_run_group_tests(tests, create_test_builder,
                                  destroy_test_builder);
}
