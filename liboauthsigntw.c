#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>

#include "logger.h"
#include "liboauthsign.h"
#include "liboauthsigntw.h"

#define FREE_IF_NOT_NULL(obj) do { if (obj != NULL) free(obj); } while (0)
#define STRDUP_CHECK_ASSIGN(rhs, str, fail) do { char* tmp = strdup( str ); if ( tmp == (char*) 0 ) return fail; rhs = tmp; } while (0)

static CURL *curl;
static int BUILDER_REF_COUNT = 0;

struct OauthBuilder {
    Param oauth_consumer_key;
    Param oauth_nonce;
    Param oauth_signature;
    Param oauth_signature_method;
    Param oauth_timestamp;
    Param oauth_token;
    Param oauth_version;

    Param consumer_secret;
    Param token_secret;
    Param http_method;
    Param base_url;
    Param *request_params;
    int req_params_size;

/*    consumer_secret, token_secret, method, url*/
    char *rest[4];
};

static char *base64_bytes(unsigned char *src, int src_size);

static char *oauth_strdup(const char *s);

static void curl_encode_len(const char *in, size_t length, char **out);

static void curl_encode(const char *in, char **out);

static void curl_decode_len(const char *in, size_t length, char **out);

static void curl_decode(const char *in, char **out);

static void free_param(Param *param);

static void set_nonce(Builder *builder);

static void set_signature_method(Builder *builder);

static void set_timestamp(Builder *builder);

static void set_oauth_version(Builder *builder);

static void set_oauth_signature(Builder *builder);

static void collect_parameters(const Builder *builder, Param ***dest, int *size);

static int compare(const void *v1, const void *v2);

/**
 * @brief      Gets the header string.
 *
 * @param[in]  builder  The builder with all the required parameters
 *
 * @return     The header string.
 */
const char *
get_header_string(Builder *builder) {
    set_nonce(builder);
    set_signature_method(builder);
    set_timestamp(builder);
    set_oauth_version(builder);

    /* Done last in order to have the values needed*/
    set_oauth_signature(builder);

    /* signature method */

    return NULL;
}

/**
 * @brief      Sets the consumer key.
 * 
 * @details    The oauth_consumer_key identifies which application is 
 * making the request. Obtain this value from checking the settings 
 * page for your application on dev.twitter.com/apps.
 * 
 * @example    oauth_consumer_key   xvz1evFS4wEEPTGEFPHBog
 *
 * @param      builder  The builder
 * @param[in]  key      The key
 */
void
set_consumer_key(Builder *builder, const char *key) {
    builder->oauth_consumer_key.value = oauth_strdup(key);

    curl_encode(builder->oauth_consumer_key.value,
                &builder->oauth_consumer_key.encoded_value);
}

/**
 * @brief      Sets the consumer secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The secret
 */
void
set_consumer_secret(Builder *builder, const char *key) {
    builder->consumer_secret.value = oauth_strdup(key);

    curl_encode(builder->consumer_secret.value,
                &builder->consumer_secret.encoded_value);
}

/**
 * @brief      Sets the token.
 * 
 * @details    The <b>oauth_token</b> parameter typically represents a user’s 
 * permission to share access to their account with your application.
 * There are a few authentication requests where this value is not passed 
 * or is a different form of token, but those are covered in detail in 
 * Obtaining access tokens. For most general-purpose requests, you will use 
 * what is referred to as an <b>access token</b>. You can generate a valid 
 * access token for your account on the settings page for your application 
 * at dev.twitter.com/apps.
 * 
 * @example    oauth_token  370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb
 *
 * @param      builder  The builder
 * @param[in]  key      The token
 */
void
set_token(Builder *builder, const char *key) {
    builder->oauth_token.value = oauth_strdup(key);

    curl_encode(builder->oauth_token.value,
                &builder->oauth_token.encoded_value);
}

/**
 * @brief      Sets the token secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The token secret
 */
void
set_token_secret(Builder *builder, const char *key) {
    builder->token_secret.value = oauth_strdup(key);

    curl_encode(builder->token_secret.value,
                &builder->token_secret.encoded_value);
}

/**
 * @brief      Sets the http method.
 * 
 * @details    The request method will almost always be GET or POST 
 * for Twitter API requests.
 *
 * @param      builder  The builder
 * @param[in]  key      The http method
 */
void
set_http_method(Builder *builder, const char *key) {
    builder->http_method.value = oauth_strdup(key);

    curl_encode(builder->http_method.value,
                &builder->http_method.encoded_value);
}

/**
 * @brief      Sets the base url.
 * 
 * @details    The base URL is the URL to which the request is directed, <em>minus any 
 * query string or hash parameters</em>. It is important to use the correct protocol here, 
 * so make sure that the "https://" or "http://" portion of the URL matches the actual 
 * request sent to the API. As a best practice, you should always be using 
 * "https://" with the Twitter API.
 *
 * @param      builder  The builder
 * @param[in]  key      The url
 */
void
set_base_url(Builder *builder, const char *key) {
    builder->base_url.value = oauth_strdup(key);

    curl_encode(builder->base_url.value,
                &builder->base_url.encoded_value);
}

/**
 * @brief      Sets the request parameters.
 *
 * @param      builder  The builder
 * @param      params   The parameters
 * @param[in]  length    The length
 */
void
set_request_params(Builder *builder, const char **params, int length) {
    int c, d;
    const char *value;

    builder->request_params = malloc(sizeof(Param) * length);
    builder->req_params_size = length;

    /* using strncat because it appends a null terminating character
    at the end of the string */
    for (c = 0; c < length; ++c) {
        d = strcspn(params[c], "=");
        builder->request_params[c].name = malloc(d);
        builder->request_params[c].name[0] = '\0';
        strncat(builder->request_params[c].name, params[c], d);

        curl_encode(builder->request_params[c].name,
                    &builder->request_params[c].encoded_name);

        value = &params[c][d + 1];
        d = strlen(value);
        builder->request_params[c].value = malloc(d);
        builder->request_params[c].value[0] = '\0';
        strncat(builder->request_params[c].value, value, d);

        curl_encode(builder->request_params[c].value,
                    &builder->request_params[c].encoded_value);
    }
}

/**
 * @brief      Creates a new builder object
 *
 * @return     a builder for collecting the required parameters
 */
Builder *
new_oauth_builder(void) {
    Builder *builder = malloc(sizeof(Builder));
    Builder temp = {{NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
                    {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
                    {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
                    {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
                    {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
                    {NULL, NULL, NULL, NULL}, NULL, 0,
                    {NULL, NULL, NULL, NULL, NULL}
    };

    temp.oauth_consumer_key.name = oauth_strdup("oauth_consumer_key");
    temp.oauth_nonce.name = oauth_strdup("oauth_nonce");
    temp.oauth_signature.name = oauth_strdup("oauth_signature");
    temp.oauth_signature_method.name = oauth_strdup("oauth_signature_method");
    temp.oauth_timestamp.name = oauth_strdup("oauth_timestamp");
    temp.oauth_token.name = oauth_strdup("oauth_token");
    temp.oauth_version.name = oauth_strdup("oauth_version");

    curl_encode(temp.oauth_consumer_key.name,
                &temp.oauth_consumer_key.encoded_name);

    curl_encode(temp.oauth_nonce.name,
                &temp.oauth_nonce.encoded_name);

    curl_encode(temp.oauth_signature.name,
                &temp.oauth_signature.encoded_name);

    curl_encode(temp.oauth_signature_method.name,
                &temp.oauth_signature_method.encoded_name);

    curl_encode(temp.oauth_timestamp.name,
                &temp.oauth_timestamp.encoded_name);

    curl_encode(temp.oauth_token.name,
                &temp.oauth_token.encoded_name);

    curl_encode(temp.oauth_version.name,
                &temp.oauth_version.encoded_name);

    memcpy(builder, &temp, sizeof(Builder));

    if (++BUILDER_REF_COUNT == 1) {
        curl = curl_easy_init();
    }

    return builder;
}

/**
 * @brief      Destroys a builder.
 *
 * @param      builder  The builder
 * @pre        Must not be null and must have been created by new_oauth_builder()
 */
void
destroy_builder(Builder **builder) {

    if (*builder != NULL && BUILDER_REF_COUNT > 0) {
        Builder *ref = *builder;
        int i;
        for (i = 0; i < 5; i++) {
            FREE_IF_NOT_NULL(ref->rest[i]);
        }
        free_param(&ref->oauth_version);
        free_param(&ref->oauth_token);
        free_param(&ref->oauth_timestamp);
        free_param(&ref->oauth_signature_method);
        free_param(&ref->oauth_signature);
        free_param(&ref->oauth_nonce);
        free_param(&ref->oauth_consumer_key);

        free(*builder);

        *builder = NULL;
        if (--BUILDER_REF_COUNT == 0) {
            curl_easy_cleanup(curl);
        }
    }
}

/**
 * @brief      Sets the oauth signature.
 * 
 * @details    The <b>oauth_signature</b> parameter contains a value which 
 * is generated by running all of the other request parameters and two 
 * secret values through a signing algorithm. The purpose of the signature 
 * is so that Twitter can verify that the request has not been modified in transit,
 * verify the application sending the request, and verify that the application has
 * authorization to interact with the user’s account.
 * The process for calculating the oauth_signature for this request is described in
 * [Creating a signature](https://dev.twitter.com/oauth/overview/creating-signatures)
 * 
 * 1. Percent encode every key and value that will be signed.
 * 2. Sort the list of parameters alphabetically[1] by encoded key[2].
 *     [2] Note: In case of two parameters with the same encoded key, the 
 *     OAuth spec says to continue sorting based on value. However, 
 *     Twitter does not accept duplicate keys in API requests.
 * 3. For each key/value pair:
 *     a. Append the encoded key to the output string.
 *     b. Append the ‘=’ character to the output string.
 *     c. Append the encoded value to the output string.
 *     d. If there are more key/value pairs remaining, append a 
 *     ‘&’ character to the output string.
 * 
 * @example    oauth_signature  tnnArxj06cWHq44gCs1OSKk/jLY=
 *
 * @param      builder  The builder
 */
static void
set_oauth_signature(Builder *builder) {
    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;

    int size, len, i;
    const Param **lst;

    collect_parameters(builder, &lst, &size);

    mem = BIO_new(BIO_s_mem());
    for (i = 0; i < size; ++i) {
        (void) BIO_write(mem, lst[i]->encoded_name, strlen(lst[i]->encoded_name));
        (void) BIO_write(mem, "=", 1);
        (void) BIO_write(mem, lst[i]->encoded_value, strlen(lst[i]->encoded_value));
        if (i + 1 < size) {
            (void) BIO_write(mem, "&", 1);
        }
    }

    /* Collect the string here... */
}

/**
 * @brief      Collects the parameters required to build the signature
 *
 * @param[in]  builder  The builder
 * @param      dest     The destination should be a reference to array of (Param*)
 * @param      size     The size is a reference to an int where the size of the
 * returned array can be stored
 */
static void
collect_parameters(const Builder *builder, Param ***dest, int *size) {
    static const int OAUTH_MEMBERS_COUNT = 6;
    const Param **lst = malloc(sizeof(Param *) * (*size));
    int i;
    *size = OAUTH_MEMBERS_COUNT + builder->req_params_size;

    lst[0] = &builder->oauth_consumer_key;
    lst[1] = &builder->oauth_nonce;
    lst[2] = &builder->oauth_signature_method;
    lst[3] = &builder->oauth_timestamp;
    lst[4] = &builder->oauth_token;
    lst[5] = &builder->oauth_version;

    for (i = OAUTH_MEMBERS_COUNT; i < size; ++i) {
        lst[i] = &builder->request_params[i - OAUTH_MEMBERS_COUNT];
    }

    qsort(lst, size, sizeof lst[0], compare);
    *dest = lst;
}

/**
 * @brief      Function for comparing parameters
 *
 * @param[in]  v1    The first parameter
 * @param[in]  v2    The second parameter
 *
 * @return     <0 if v1 goes before v2
 *             0  if vi is equivalent to v2
 *             >0 if v1 goes after v2
 */
static int
compare(const void *v1, const void *v2) {
    const Param *p1 = (const Param *) v1;
    const Param *p2 = (const Param *) v2;
    int r = strcmp(p1->encoded_name, p2->encoded_name);
    if (r == 0) /* This should never happen, but just
                   * for the sake of completeness, we will leave this in */
        r = strcmp(p1->encoded_value, p2->encoded_value);
    return r;
}

/**
 * @brief      Generates random alphanum strings
 * 
 * @details    The oauth_nonce parameter is a unique token your application
 * should generate for each unique request. Twitter will use this 
 * value to determine whether a request has been submitted multiple times.
 * The value for this request was generated by base64 encoding 
 * 32 bytes of random data, and stripping out all non-word characters, but 
 * any approach which produces a relatively random alphanumeric string 
 * should be OK here.
 * 
 * @example    oauth_nonce  kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg
 *
 * @param      builder  The builder
 */
static void
set_nonce(Builder *builder) {
    char *random_str = base64_bytes(NULL, 32);
    char *collect = random_str;
    char *run = random_str;
    while (*run) {
        if (isalnum(*run)) {
            *collect++ = *run;
        } else {
            *run = '\0';
        }
        ++run;
    }

    builder->oauth_nonce.value = random_str;

    curl_encode(random_str, &builder->oauth_nonce.encoded_value);
}

/**
 * @brief      Sets the signature method.
 * 
 * @details    The <b>oauth_signature_method</b> used by Twitter is <b>HMAC-SHA1</b>. 
 * This value should be used for any authorized request sent to Twitter’s API.
 * 
 * @example    oauth_signature_method   HMAC-SHA1
 *
 * @param      builder  The builder
 */
static void
set_signature_method(Builder *builder) {
    builder->oauth_signature_method.value = oauth_strdup("HMAC-SHA1");

    curl_encode(builder->oauth_signature_method.value,
                &builder->oauth_signature_method.encoded_value);
}

/**
 * @brief      Sets the timestamp.
 * 
 * @details    The <b>oauth_timestamp parameter</b> indicates when the request 
 * was created. This value should be the number of seconds since the Unix 
 * epoch at the point the request is generated, and should be easily generated
 * in most programming languages. Twitter will reject requests which were 
 * created too far in the past, so it is important to keep the clock of the 
 * computer generating requests in sync with NTP.
 * 
 * @example    oauth_timestamp  1318622958
 *
 * @param      builder  The builder
 */
static void
set_timestamp(Builder *builder) {
    time_t now;
    char timestamp[20];
    (void) snprintf(timestamp, sizeof timestamp, "%ld", (long) now);
    builder->oauth_timestamp.value = oauth_strdup(timestamp);

    curl_encode(builder->oauth_timestamp.value,
                &builder->oauth_timestamp.encoded_value);
}

/**
 * @brief      Sets the oauth version.
 * 
 * @details    The oauth_version parameter should always be 1.0 for any 
 * request sent to the Twitter API.
 * 
 * @example    oauth_version    1.0
 *
 * @param      builder  The builder
 */
static void
set_oauth_version(Builder *builder) {
    builder->oauth_version.value = oauth_strdup("1.0");

    curl_encode(builder->oauth_version.value,
                &builder->oauth_version.encoded_value);
}

/**
 *    Given an array of bytes, encodes them to base64 and returns the result
 *    IT IS THE RESPONSIBILITY OF THE CALLER TO FREE RETURNED POINTER
 */
static char *
base64_bytes(unsigned char *src, int src_size) {
    BIO *b64 = NULL, *mem = NULL;
    BUF_MEM *bptr = NULL;
    char *bytes = NULL;
    int freesrc = 0;

    if (src == NULL) {
        src = malloc(src_size);
        if (!RAND_bytes(src, src_size)) {
            e_log("The random generator is proving difficult");
            return (char *) NULL;
        }
        freesrc = 1;
    }

    /*Create a base64 filter/sink*/
    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        e_log("Could not create a base64 filter!");
        return (char *) NULL;
    }

    /*Create a memory source, this is where everything will end up eventually*/
    if ((mem = BIO_new(BIO_s_mem())) == NULL) {
        e_log("Could not allocate storage for the conversion");
        return (char *) NULL;
    }

    /* Chain them: --> b64 >|> mem */
    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);

    /*Write the bytes*/
    BIO_write(mem, src, src_size);
    BIO_flush(b64);

    /*Now remove the base64 filter: -->mem, and write a null terminator*/
    mem = BIO_pop(b64);
    BIO_write(mem, "\0", 1);

    /*Retrieve the underlying memory pointer*/
    BIO_get_mem_ptr(mem, &bptr);

    /*Allocate memory for the internal buffer and copy it to the new location*/
    STRDUP_CHECK_ASSIGN(bytes, bptr->data, (char *) 0);

    /*Cleanup*/
    BIO_set_close(mem, BIO_CLOSE);
    BIO_free_all(mem);
    if (freesrc)
        free(src);

    return bytes;
}

/**
 * @brief      Creates a copy of a string
 *
 * @param[in]  s     The string to copy
 *
 * @return     The copy of the string or null if the copying failed
 */
static char *
oauth_strdup(const char *s) {
    char *dest = NULL;
    STRDUP_CHECK_ASSIGN(dest, s, (char *) 0);
    return dest;
}

/**
 * @brief      percent-encodes a given string
 *
 * @param[in]  in      The string to encode
 * @param[in]  length  The length
 * @param      out     The address of a pointer to hold the encoded string
 */
static void
curl_encode_len(const char *in, size_t length, char **out) {
    char *encode = curl_easy_escape(curl, in, length);
    *out = oauth_strdup(encode);
    curl_free(encode);
}

/**
 * @brief      percent-encodes a given string
 *
 * @param[in]  in    The string to encode
 * @param      out   The address of a pointer to hold the encoded string
 */
static void
curl_encode(const char *in, char **out) {
    char *encode = curl_easy_escape(curl, in, 0);
    *out = oauth_strdup(encode);
    curl_free(encode);
}

/**
 * @brief      Decodes a given string (opposite of encode)
 *
 * @param[in]  in      The encoded string to decode
 * @param[in]  length  The length of the encoded string
 * @param      out     The address of a pointer to hold the decoded string
 */
static void
curl_decode_len(const char *in, size_t length, char **out) {
    int len;
    char *decode = curl_easy_unescape(curl, in, length, &len);
    *out = oauth_strdup(decode);
    curl_free(decode);
}

/**
 * @brief      Decodes a given string (opposite of encode)
 *
 * @param[in]  in      The encoded string to decode
 * @param      out     The address of a pointer to hold the decoded string
 */
static void
curl_decode(const char *in, char **out) {
    int len;
    char *decode = curl_easy_unescape(curl, in, 0, &len);
    *out = oauth_strdup(decode);
    curl_free(decode);
}

/**
 * @brief      Helper to free the params of a Builder object
 *
 * @param      param  A pointer to the param to deallocate memory for
 */
static void
free_param(Param *param) {
    FREE_IF_NOT_NULL(param->name);
    FREE_IF_NOT_NULL(param->value);
    FREE_IF_NOT_NULL(param->encoded_name);
    FREE_IF_NOT_NULL(param->encoded_value);
}

/* Example of using curl to send POST request with params
 curl -v -L -d "lat=41.225&lon=-73.1" http://localhost:5000/pulse*/
