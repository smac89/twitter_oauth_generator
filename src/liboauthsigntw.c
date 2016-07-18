#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "logger.h"
#include "liboauthsign.h"
#include "liboauthsigntw.h"

#define FREE_IF_NOT_NULL(obj) do { if ((obj) != NULL) free(obj); } while (0)
#define STRDUP_CHECK_ASSIGN(rhs, str, fail) do { char* tmp = strdup( str ); if ( tmp == (char*) 0 ) return fail; rhs = tmp; } while (0)

/**
 * This is an X-MACRO which helps in reducing the amount of time
 * spent retyping these members in the code
 * 
 * @details    To make use of these, simply define an X function which takes
 * a two arguements - type and name and then do whatever you want with them
 * 
 * @example    Examples of using these can be found in the code
 */
#define X_BUILDER_OAUTH_MEMBERS \
    X(Param,  oauth_consumer_key) \
    X(Param,  oauth_nonce) \
    X(Param,  oauth_signature) \
    X(Param,  oauth_signature_method) \
    X(Param,  oauth_timestamp) \
    X(Param,  oauth_token) \
    X(Param,  oauth_version)

static CURL *curl;
static int BUILDER_REF_COUNT = 0;

struct OauthBuilder {

/**
 * @brief      This X function creates some struct members
 *
 * @param      type  The type
 * @param      name  The name of the member
 */
#define X(type, name) type name;
    X_BUILDER_OAUTH_MEMBERS
#undef X
    Param consumer_secret;
    Param token_secret;
    Param http_method;
    Param base_url;
    Param *request_params;
    int req_params_size;
};

static char *base64_bytes(unsigned char *src, int src_size);

static char *oauth_strdup(const char *s);

static void curl_encode_len(const char *in, size_t length, char **out);

static void curl_encode(const char *in, char **out);

static void curl_decode_len(const char *in, size_t length, char **out);

static void curl_decode(const char *in, char **out);

static BUF_MEM *create_signature_base(const Builder *builder, const char *parameter_string, size_t len);

static BUF_MEM *get_signing_key(const Builder *builder);

static BUF_MEM *collect_parameters(const Builder *builder);

static void free_param(Param *param);

static void set_nonce(Builder *builder);

static void set_signature_method(Builder *builder);

static void set_timestamp(Builder *builder);

static void set_oauth_version(Builder *builder);

static void set_signature(Builder *builder);

static int compare(const void *v1, const void *v2);


const char *
get_header_string(Builder *builder) {
    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;

    set_nonce(builder);
    set_signature_method(builder);
    set_timestamp(builder);
    set_oauth_version(builder);

    /* Done last in order to have the values needed*/
    set_signature(builder);

    mem = BIO_new(BIO_s_mem());
    BIO_write(mem, "OAuth ", 6);



    /* signature method */

    return NULL;
}

void
set_consumer_key(Builder *builder, const char *key) {
    builder->oauth_consumer_key.value = oauth_strdup(key);

    curl_encode(builder->oauth_consumer_key.value,
                &builder->oauth_consumer_key.encoded_value);
}

void
set_consumer_secret(Builder *builder, const char *key) {
    builder->consumer_secret.value = oauth_strdup(key);

    curl_encode(builder->consumer_secret.value,
                &builder->consumer_secret.encoded_value);
}

void
set_token(Builder *builder, const char *key) {
    builder->oauth_token.value = oauth_strdup(key);

    curl_encode(builder->oauth_token.value,
                &builder->oauth_token.encoded_value);
}

void
set_token_secret(Builder *builder, const char *key) {
    builder->token_secret.value = oauth_strdup(key);

    curl_encode(builder->token_secret.value,
                &builder->token_secret.encoded_value);
}

void
set_http_method(Builder *builder, const char *key) {
    builder->http_method.value = oauth_strdup(key);

    curl_encode(builder->http_method.value,
                &builder->http_method.encoded_value);
}

void
set_base_url(Builder *builder, const char *key) {
    builder->base_url.value = oauth_strdup(key);

    curl_encode(builder->base_url.value,
                &builder->base_url.encoded_value);
}

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

Builder *
new_oauth_builder(void) {
    Builder *builder = malloc(sizeof(Builder));
    Builder temp = {

/**
 * @brief      This X function initializes some of the struct members
 *
 * @param      _       Unused
 * @param      member  The name of the member
 */
#define X(_, member) {#member, NULL, NULL, NULL},
            X_BUILDER_OAUTH_MEMBERS
#undef X
            {NULL, NULL, NULL, NULL},
            {NULL, NULL, NULL, NULL},
            {NULL, NULL, NULL, NULL},
            {NULL, NULL, NULL, NULL},
            NULL,
            0
    };

/**
 * @brief      This X function percent-encodes some of the struct members
 *
 * @param      _    Unused
 * @param      member  The member
 */
#define X(_, member) curl_encode(temp.member.name, &temp.member.encoded_name);
    X_BUILDER_OAUTH_MEMBERS
#undef X

    memcpy(builder, &temp, sizeof(Builder));

    if (++BUILDER_REF_COUNT == 1) {
        curl = curl_easy_init();
    }

    return builder;
}

void
destroy_builder(Builder **builder) {

    if (*builder != NULL && BUILDER_REF_COUNT > 0) {
        Builder *ref = *builder;
        if (ref->request_params != NULL) {
            int i;
            for (i = 0; i < ref->req_params_size; ++i) {
                free_param(&ref->request_params[i]);
            }
            ref->request_params = NULL;
        }
        free_param(&ref->base_url);
        free_param(&ref->http_method);
        free_param(&ref->token_secret);
        free_param(&ref->consumer_secret);
/**
 * @brief      This X function frees some of the struct members
 *
 * @param      _       Unused
 * @param      member  The member
 */
#define X(_, member) free_param(&ref->member);
        X_BUILDER_OAUTH_MEMBERS
#undef X

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
 * 
 * @example    oauth_signature  tnnArxj06cWHq44gCs1OSKk/jLY=
 *
 * @param      builder  The builder
 */
static void
set_signature(Builder *builder) {
    BUF_MEM *bptr = NULL, *base = NULL, *key = NULL;
    unsigned char sig[SHA_DIGEST_LENGTH] = {0};

    int len;

    bptr = collect_parameters(builder);

    base = create_signature_base(builder, bptr->data, bptr->length);
    key = get_signing_key(builder);

    /**
     * Finally, the signature is calculated by passing the signature base string and signing key to the
     * HMAC-SHA1 hashing algorithm.
     *
     * The output of the HMAC signing function is a binary string. This needs to be base64 encoded
     * to produce the signature string.
     */
    (void) HMAC(EVP_sha1(), key->data, key->length, (unsigned char *) base->data, base->length, sig,
                (unsigned int *) &len);

    builder->oauth_signature.value = base64_bytes(sig, len);
    curl_encode(builder->oauth_signature.value, &builder->oauth_signature.encoded_value);

    BUF_MEM_free(key);
    BUF_MEM_free(base);
    BUF_MEM_free(bptr);
}

/**
 * @brief      Gets the signing key.
 * 
 * @details    The value which identifies your application to Twitter is called the
 * consumer secret and can be found by going to dev.twitter.com/apps and viewing the 
 * settings page for your application. This will be the same for every request your 
 * application sends.
 * 
 * @example    Consumer secret kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw
 * 
 * The value which identifies the account your application is acting on behalf of is called 
 * the oauth token secret. This value can be obtained in several ways, all of which are 
 * described at Obtaining access tokens.
 * 
 * @example    OAuth token secret  LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE
 * 
 * Both of these values need to be combined to form a *signing key* which will be used to 
 * generate the signature. The signing key is simply the percent encoded consumer secret, 
 * followed by an ampersand character ‘&’, followed by the percent encoded token secret
 * 
 * Note that there are some flows, such as when obtaining a request token, where the token 
 * secret is not yet known. In this case, the signing key should consist of the [percent 
 * encoded](https://dev.twitter.com/oauth/overview/percent-encoding-parameters) *consumer secret* followed by an ampersand character ‘&’.
 *
 * @param[in]  builder  The builder
 *
 * @return     The signing key.
 */
static BUF_MEM *
get_signing_key(const Builder *builder) {
    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;

    mem = BIO_new(BIO_s_mem());
    if (mem) {
        BIO_write(mem, builder->consumer_secret.encoded_value, strlen(builder->consumer_secret.encoded_value));
        BIO_write(mem, "&", 1);
        BIO_write(mem, builder->token_secret.encoded_value, strlen(builder->token_secret.encoded_value));
    }

    BIO_get_mem_ptr(mem, bptr);
    BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free_all(mem);

    return bptr;
}

/**
 * @brief      Gets the parameters
 *
 * @details    In the HTTP request the parameters are URL encoded, but you should collect 
 * the raw values. In addition to the request parameters, every *oauth_** parameter needs to be included 
 * in the signature, so collect those too.
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
 *     d. If there are more key/value pairs remaining, append a '&' character to the output string.
 *
 * @param[in]  builder  The builder
 *
 * @return     A pointer to a buffer holding the parameter string
 */
static BUF_MEM *
collect_parameters(const Builder *builder) {
/**
 * @brief      This X function is used to count the number of members
 */
#define X(_, __) +1
    static const int OAUTH_MEMBERS_COUNT = -1/* Start at -1 because we don't use oauth_signature here */
                                           X_BUILDER_OAUTH_MEMBERS;
#undef X

    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;
    int size = OAUTH_MEMBERS_COUNT + builder->req_params_size, i;

    const Param **lst = malloc(sizeof(Param *) * size);

    /* Didn't use X-functions here because we don't have
     oauth_signature yet
     */
    lst[0] = &builder->oauth_consumer_key;
    lst[1] = &builder->oauth_nonce;
    lst[2] = &builder->oauth_signature_method;
    lst[3] = &builder->oauth_timestamp;
    lst[4] = &builder->oauth_token;
    lst[5] = &builder->oauth_version;

    for (i = OAUTH_MEMBERS_COUNT; i < size; ++i) {
        lst[i] = &builder->request_params[i - OAUTH_MEMBERS_COUNT];
    }

    qsort(lst, (unsigned int) size, sizeof lst[0], compare);

    mem = BIO_new(BIO_s_mem());
    if (mem) {
        for (i = 0; i < size; ++i) {
            (void) BIO_write(mem, lst[i]->encoded_name, strlen(lst[i]->encoded_name));
            (void) BIO_write(mem, "=", 1);
            (void) BIO_write(mem, lst[i]->encoded_value, strlen(lst[i]->encoded_value));
            if (i + 1 < size) {
                (void) BIO_write(mem, "&", 1);
            }
        }

        BIO_get_mem_ptr(mem, bptr);
        BIO_set_close(mem, BIO_NOCLOSE);
        BIO_free_all(mem);
    }

    free(lst);

    return bptr;
}

/**
 * @brief      Creates a signature base.
 * 
 * @details    The three values collected so far must be joined to make a single string, from 
 * which the signature will be generated. This is called the *signature base* string 
 * by the OAuth specification.
 * 
 * To encode the HTTP method, base URL, and parameter string into a single string:
 *     1. Convert the HTTP Method to uppercase and set the output string equal to this value.
 *     2. Append the ‘&’ character to the output string.
 *     3. Percent encode the URL and append it to the output string.
 *     4. Append the ‘&’ character to the output string.
 *     5. Percent encode the parameter string and append it to the output string.
 *
 * @param[in]  builder           The builder
 * @param[in]  parameter_string  The parameter string
 * @param[in]  len               The length
 *
 * @return     A buffer containing the signature base
 */
static BUF_MEM *
create_signature_base(const Builder *builder, const char *parameter_string, size_t len) {
    BIO *mem = NULL;
    BUF_MEM *bptr = NULL;
    char *encoded_param;
    curl_encode_len(parameter_string, len, &encoded_param);

    mem = BIO_new(BIO_s_mem());
    if (mem) {
        BIO_write(mem, builder->http_method.value, strlen(builder->http_method.value));
        BIO_write(mem, "&", 1);
        BIO_write(mem, builder->base_url.encoded_value, strlen(builder->base_url.encoded_value));
        BIO_write(mem, "&", 1);
        BIO_write(mem, encoded_param, strlen(encoded_param));
    }

    BIO_get_mem_ptr(mem, bptr);
    BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free_all(mem);

    return bptr;
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
    if (r == 0) /* (r == 0) This should never happen, but just
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
    time_t now = time(NULL);
    char timestamp[20];
    (void) snprintf(timestamp, sizeof timestamp, "%ld", (long int) now);
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
    bytes = oauth_strdup(bptr->data);

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
