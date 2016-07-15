/* liboauthsign.c - OAuth signature generation routine
**
** http://tools.ietf.org/html/rfc5849
**
** Copyright © 2010 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
**
** For commentary on this license please see http://acme.com/license.html
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sysexits.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include "logger.h"

#include "liboauthsign.h"

#define MALLOC_CHECK_ASSIGN(rhs,size,fail) do { void* tmp = malloc( size ); if ( tmp == (void*) 0 ) return fail; rhs = tmp; } while (0)
#define STRDUP_CHECK_ASSIGN(rhs,str,fail) do { char* tmp = strdup( str ); if ( tmp == (char*) 0 ) return fail; rhs = tmp; } while (0)
#define PERCENT_ENCODE_CHECK_ASSIGN(rhs,str,fail) do { char* tmp = percent_encode( str ); if ( tmp == (char*) 0 ) return fail; rhs = tmp; } while (0)
#define FREE_IF_NOT_NULL(obj) do { if (obj != NULL) free(obj); } while (0)

#define max(a,b) ((a)>(b)?(a):(b))

static char* percent_encode( const char* str );
static char* base64_bytes(unsigned char* src, int src_size);
static int compare( const void* v1, const void* v2 );
static void url_decode( char* to, const char* from );
static int from_hexit( char c );

typedef struct {
    char* name;
    char* value;
    char* encoded_name;
    char* encoded_value;
} Param;

typedef enum {
    CONSUMER_SECRET = 0,
    TOKEN_SECRET,
    METHOD,
    URL,
    URL_PARAMS
} RestPos;

/**/
struct OauthBuilder {
    Param oauth_consumer_key;
    Param oauth_nonce;
    Param oauth_signature;
    Param oauth_signature_method;
    Param oauth_timestamp;
    Param oauth_token;
    Param oauth_version;

/*    consumer_secret, token_secret, method, url, extra_params*/    
    char *rest[5];
};


static CURL* curl;
static int BUILDER_REF_COUNT = 0;
static int show_sbs = 0;

#if defined(__FreeBSD__)
    srandomdev();
#else
    srandom( (int) time( (time_t*) 0 ) ^ getpid() );
#endif

void oauth_show_sbs( void )
{
    show_sbs = 1;
}


char*
oauth_sign( int query_mode, char* consumer_key, const char* consumer_key_secret, char* token, const char* token_secret, const char* method, const char* url, int paramc, char** paramv )
{
    char* oauth_signature_method;
    char oauth_timestamp[20];
    char *oauth_nonce;
    char* oauth_version;
    time_t now;
    char* qmark;
    char* query_string;
    int n_ampers;
    int max_query_params, n_query_params;
    Param* query_params;
    int max_post_params, n_post_params;
    Param* post_params;
    int max_proto_params, n_proto_params;
    Param* proto_params;
    int max_all_params, n_all_params;
    Param* all_params;
    int i;
    char* cp;
    char* equal;
    char* value;
    char* amper;
    char* base_url;
    char* encoded_base_url;
    char* qmark2;
    size_t params_string_len;
    char* params_string;
    char* encoded_params_string;
    char* encoded_consumer_key_secret;
    char* encoded_token_secret;
    size_t base_string_len;
    char* base_string;
    size_t key_len;
    char* key;
    unsigned char hmac_block[SHA_DIGEST_LENGTH];
    char *oauth_signature;
    size_t authorization_len;
    char* authorization;
    
    if ( query_mode && paramc > 0 )
        return (char*) 0;
    
    /* Assign values to the rest of the required protocol params. */
    oauth_signature_method = "HMAC-SHA1";
    now = time( (time_t*) 0 );
    (void) snprintf( oauth_timestamp, sizeof(oauth_timestamp), "%ld", (long) now );

    oauth_nonce = base64_bytes(NULL, 32);
    oauth_version = "1.0";
    
    /* Parse the URL's query-string params. */
    qmark = strchr( url, '?' );
    if ( qmark == (char*) 0 )
    {
        STRDUP_CHECK_ASSIGN( query_string, "", (char*) 0 );
        max_query_params = 1;       /* avoid malloc(0) */
    }
    else
    {
        STRDUP_CHECK_ASSIGN( query_string, qmark + 1, (char*) 0 );
        n_ampers = 0;
        for ( i = 0; query_string[i] != '\0'; ++i )
            if ( query_string[i] == '&' )
                ++n_ampers;
            max_query_params = n_ampers + 1;
    }
    MALLOC_CHECK_ASSIGN( query_params, sizeof(Param) * max_query_params, (char*) 0 );
    n_query_params = 0;
    if ( qmark != (char*) 0 )
    {
        cp = query_string;
        for (;;)
        {
            equal = strchr( cp, '=' );
            amper = strchr( cp, '&' );
            if ( equal == (char*) 0 || ( amper != (char*) 0 && amper < equal ) )
            {
                value = "";
            }
            else
            {
                *equal = '\0';
                value = equal + 1;
            }
            if ( amper != (char*) 0 )
                *amper = '\0';
            STRDUP_CHECK_ASSIGN( query_params[n_query_params].name, cp, (char*) 0 );
            STRDUP_CHECK_ASSIGN( query_params[n_query_params].value, value, (char*) 0 );
            url_decode( query_params[n_query_params].name, query_params[n_query_params].name );
            url_decode( query_params[n_query_params].value, query_params[n_query_params].value );
            ++n_query_params;
            if ( amper == (char*) 0 )
                break;
            cp = amper + 1;
        }
    }
    
    /* Add in the optional POST params. */
    max_post_params = max( paramc, 1 );     /* avoid malloc(0) */
    MALLOC_CHECK_ASSIGN( post_params, sizeof(Param) * max_post_params, (char*) 0 );
    n_post_params = 0;
    for ( n_post_params = 0; n_post_params < paramc; ++n_post_params )
    {
        STRDUP_CHECK_ASSIGN( post_params[n_post_params].name, paramv[n_post_params], (char*) 0 );
        equal = strchr( post_params[n_post_params].name, '=' );
        if ( equal == (char*) 0 )
            post_params[n_post_params].value = "";
        else
        {
            *equal = '\0';
            post_params[n_post_params].value = equal + 1;
        }
    }
    
    /* Make the protocol params. */
    max_proto_params = 7;
    MALLOC_CHECK_ASSIGN( proto_params, sizeof(Param) * max_proto_params, (char*) 0 );
    n_proto_params = 0;
    if ( strlen( consumer_key ) > 0 )
    {
        proto_params[n_proto_params].name = "oauth_consumer_key";
        proto_params[n_proto_params].value = consumer_key;
        ++n_proto_params;
    }
    if ( strlen( token ) > 0 )
    {
        proto_params[n_proto_params].name = "oauth_token";
        proto_params[n_proto_params].value = token;
        ++n_proto_params;
    }
    proto_params[n_proto_params].name = "oauth_signature_method";
    proto_params[n_proto_params].value = oauth_signature_method;
    ++n_proto_params;
    proto_params[n_proto_params].name = "oauth_timestamp";
    proto_params[n_proto_params].value = oauth_timestamp;
    ++n_proto_params;
    proto_params[n_proto_params].name = "oauth_nonce";
    proto_params[n_proto_params].value = oauth_nonce;
    ++n_proto_params;
    proto_params[n_proto_params].name = "oauth_version";
    proto_params[n_proto_params].value = oauth_version;
    ++n_proto_params;
    
    /* Percent-encode and concatenate the parameter lists. */
    max_all_params = max_query_params + max_post_params + max_proto_params ;
    MALLOC_CHECK_ASSIGN( all_params, sizeof(Param) * max_all_params, (char*) 0 );
    n_all_params = 0;
    for ( i = 0; i < n_query_params; ++i )
    {
        PERCENT_ENCODE_CHECK_ASSIGN( query_params[i].encoded_name, query_params[i].name, (char*) 0 );
        PERCENT_ENCODE_CHECK_ASSIGN( query_params[i].encoded_value, query_params[i].value, (char*) 0 );
        all_params[n_all_params] = query_params[i];
        ++n_all_params;
    }
    for ( i = 0; i < n_post_params; ++i )
    {
        PERCENT_ENCODE_CHECK_ASSIGN( post_params[i].encoded_name, post_params[i].name, (char*) 0 );
        PERCENT_ENCODE_CHECK_ASSIGN( post_params[i].encoded_value, post_params[i].value, (char*) 0 );
        all_params[n_all_params] = post_params[i];
        ++n_all_params;
    }
    for ( i = 0; i < n_proto_params; ++i )
    {
        PERCENT_ENCODE_CHECK_ASSIGN( proto_params[i].encoded_name, proto_params[i].name, (char*) 0 );
        PERCENT_ENCODE_CHECK_ASSIGN( proto_params[i].encoded_value, proto_params[i].value, (char*) 0 );
        all_params[n_all_params] = proto_params[i];
        ++n_all_params;
    }
    
    /* Sort the combined & encoded parameters. */
    qsort( all_params, n_all_params, sizeof(Param), compare );
    
    /* Construct the signature base string.  First get the base URL. */
    STRDUP_CHECK_ASSIGN( base_url, url, (char*) 0 );
    qmark2 = strchr( base_url, '?' );
    if ( qmark2 != (char*) 0 )
        *qmark2 = '\0';
    PERCENT_ENCODE_CHECK_ASSIGN( encoded_base_url, base_url, (char*) 0 );
    
    /* Next make the parameters string.
    **
    ** There's a weirdness with the spec here.  According to RFC5849
    ** sections 3.4.1.3.2 and 3.4.1.1, we should first concatenate the
    ** encoded parameters together using "=" and "&", then percent-encode
    ** the whole string.  However according to Twitter's implementation
    ** guide at http://dev.twitter.com/pages/auth we should concatenate
    ** the encoded parameters using "%3D" and "%26", which are the
    ** percent-encoded versions of "=" and "&", and then *not*
    ** percent-encode the whole string.  The difference is that
    ** if we use the RFC's method, then anything that got percent-encoded
    ** in the parameters gets percent-encoded a second time, resulting
    ** in constructs like "%25xx" instead of "%xx".  We currently implement
    ** the RFC's version, with the double-encoded percents, but
    ** may switch to the other if there are interoperability problems.
    */
    params_string_len = 0;
    for ( i = 0; i < n_all_params; ++i )
        params_string_len += 3 + strlen( all_params[i].encoded_name ) + 3 + strlen( all_params[i].encoded_value );
    MALLOC_CHECK_ASSIGN( params_string, params_string_len + 1, (char*) 0 );
    params_string[0] = '\0';
    for ( i = 0; i < n_all_params; ++i )
    {
        if ( i != 0 )
            (void) strcat( params_string, "&" );
        (void) strcat( params_string, all_params[i].encoded_name );
        (void) strcat( params_string, "=" );
        (void) strcat( params_string, all_params[i].encoded_value );
    }
    PERCENT_ENCODE_CHECK_ASSIGN( encoded_params_string, params_string, (char*) 0 );
    
    /* Put together all the parts of the base string. */
    base_string_len = strlen( method ) + 1 + strlen( encoded_base_url ) + 1 + strlen( encoded_params_string );
    MALLOC_CHECK_ASSIGN( base_string, base_string_len + 1, (char*) 0 );
    (void) sprintf( base_string, "%s&%s&%s", method, encoded_base_url, encoded_params_string );
    
    /* Write out the base string, if requested. */
    if ( show_sbs )
        (void) fprintf( stderr, "%s\n", base_string );
    
    /* Calculate the signature. */
    PERCENT_ENCODE_CHECK_ASSIGN( encoded_consumer_key_secret, consumer_key_secret, (char*) 0 );
    PERCENT_ENCODE_CHECK_ASSIGN( encoded_token_secret, token_secret, (char*) 0 );
    key_len = strlen( encoded_consumer_key_secret ) + 1 + strlen( encoded_token_secret );
    MALLOC_CHECK_ASSIGN( key, key_len + 1 , (char*) 0 );
    (void) sprintf( key, "%s&%s", encoded_consumer_key_secret, encoded_token_secret );
    (void) HMAC( EVP_sha1(), key, strlen( key ), (unsigned char*) base_string, strlen( base_string ), hmac_block, (unsigned int*) 0 );
    oauth_signature = base64_bytes( hmac_block, SHA_DIGEST_LENGTH );
    
    /* Add the signature to the request too. */
    proto_params[n_proto_params].name = "oauth_signature";
    proto_params[n_proto_params].value = oauth_signature;
    PERCENT_ENCODE_CHECK_ASSIGN( proto_params[n_proto_params].encoded_name, proto_params[n_proto_params].name, (char*) 0 );
    PERCENT_ENCODE_CHECK_ASSIGN( proto_params[n_proto_params].encoded_value, proto_params[n_proto_params].value, (char*) 0 );
    all_params[n_all_params] = proto_params[n_proto_params];
    ++n_proto_params;
    ++n_all_params;
    
    if ( query_mode )
    {
        /* Generate the authorization query parameters. */
        authorization_len = 1;
        for ( i = 0; i < n_proto_params; ++i )
            authorization_len += strlen( proto_params[i].encoded_name ) + strlen( proto_params[i].encoded_value ) + 2;
        MALLOC_CHECK_ASSIGN( authorization, authorization_len + 1 , (char*) 0 );
        if ( strchr( url, '?' ) == (char*) 0 )
            (void) strcpy( authorization, "?" );
        else
            (void) strcpy( authorization, "&" );
        for ( i = 0; i < n_proto_params; ++i )
        {
            if ( i > 0 ) {
                (void) strcat( authorization, "&" );
            }

            (void) strcat( authorization, proto_params[i].encoded_name );
            (void) strcat( authorization, "=" );
            (void) strcat( authorization, proto_params[i].encoded_value );
        }
    }
    else
    {
        /* Generate the Authorization header value. */
        authorization_len = 6;
        for ( i = 0; i < n_proto_params; ++i )
            authorization_len += strlen( proto_params[i].encoded_name ) + strlen( proto_params[i].encoded_value ) + 5;
        MALLOC_CHECK_ASSIGN( authorization, authorization_len + 1 , (char*) 0 );
        (void) strcpy( authorization, "OAuth " );
        for ( i = 0; i < n_proto_params; ++i )
        {
            if ( i > 0 ) {
                (void) strcat( authorization, ", " );
            }

            (void) strcat( authorization, proto_params[i].encoded_name );
            (void) strcat( authorization, "=\"" );
            (void) strcat( authorization, proto_params[i].encoded_value );
            (void) strcat( authorization, "\"" );
        }
    }
    
    /* Free everything except authorization. */
    free( query_string );

    for ( i = 0; i < n_query_params; ++i ) {
        free( query_params[i].name );
        free( query_params[i].value );
    }
    for ( i = 0; i < n_post_params; ++i ) {
        free( (void*) post_params[i].name );
    }

    for ( i = 0; i < n_all_params; ++i ) {
        free( all_params[i].encoded_name );
        free( all_params[i].encoded_value );
    }

    free( query_params );
    free( post_params );
    free( proto_params );
    free( all_params );
    free( base_url );
    free( encoded_base_url );
    free( params_string );
    free( encoded_params_string );
    free( encoded_consumer_key_secret );
    free( encoded_token_secret );
    free( base_string );
    free( key );
    free( oauth_nonce );
    free( oauth_signature );
    
    return authorization;
}

static char*
percent_encode( const char* str ) {
    int max_len;
    char* new_str;
    const char* cp;
    char* new_cp;
    char* ok = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    char to_hexit[] = "0123456789ABCDEF";
    
    max_len = strlen( str ) * 3;
    MALLOC_CHECK_ASSIGN( new_str, max_len + 1, (char*) 0 );
    for ( cp = str, new_cp = new_str; *cp != '\0'; ++cp ) {
        if ( strchr( ok, *cp ) != (char*) 0 )
            *new_cp++ = *cp;
        else {
            *new_cp++ = '%';
            *new_cp++ = to_hexit[ ( (*cp) >> 4 ) & 0xf ];
            *new_cp++ = to_hexit[ (*cp) & 0xf ];
        }
    }
    *new_cp = '\0';
    return new_str;
}


static int
compare( const void* v1, const void* v2 ) {
    const Param* p1 = (const Param*) v1;
    const Param* p2 = (const Param*) v2;
    int r = strcmp( p1->encoded_name, p2->encoded_name );
    if ( r == 0 )
        r = strcmp( p1->encoded_value, p2->encoded_value );
    return r;
}


/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
static void
url_decode( char* to, const char* from ) {
    for ( ; *from != '\0'; ++to, ++from ) {
        if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) ) {
            *to = from_hexit( from[1] ) * 16 + from_hexit( from[2] );
            from += 2;
        }
        else if ( *from == '+' )
            *to = ' ';
        else
            *to = *from;
    }
    *to = '\0';
}


static int
from_hexit( char c ) {
    if ( c >= '0' && c <= '9' )
        return c - '0';
    if ( c >= 'a' && c <= 'f' )
        return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' )
        return c - 'A' + 10;
    return 0;           /* shouldn't happen, we're guarded by isxdigit() */
}

/**
 *    Given an array of bytes, encodes them to base64 and returns the result
 *    IT IS THE RESPONSIBILITY OF THE CALLER TO FREE RETURNED POINTER
 */
static char*
base64_bytes(unsigned char* src, int src_size) {
    BIO *b64 = NULL, *mem = NULL;
    BUF_MEM *bptr = NULL;
    char *bytes = NULL;
    int freesrc = 0;

    if (src == NULL) {
        src = malloc(src_size);
        if (!RAND_bytes( src, src_size)) {
            e_log("The random generator is proving difficult");
            return ( char* )NULL;
        }
        freesrc = 1;
    }

    /*Create a base64 filter/sink*/
    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        e_log("Could not create a base64 filter!");
        return ( char* )NULL;
    }

    /*Create a memory source, this is where everything will end up eventually*/
    if ((mem = BIO_new(BIO_s_mem())) == NULL) {
        e_log("Could not allocate storage for the conversion");
        return ( char* )NULL;
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
    STRDUP_CHECK_ASSIGN(bytes, bptr->data, (char *)0);

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
static char*
oauth_strdup(const char* s) {
    char *dest = NULL;
    STRDUP_CHECK_ASSIGN(dest, s, (char *)0);
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
curl_encode(const char* in, size_t length, char **out) {
    char *encode = curl_easy_escape(curl, in, length);
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
curl_decode(const char* in, size_t length, char **out) {
    int len;
    char *decode = curl_easy_unescape(curl, in, length, &len);
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
        }
        ++run;
    }
    *collect = '\0';

    builder->oauth_nonce.value = random_str;
    curl_encode(random_str, strlen(random_str),
        &builder->oauth_nonce.encoded_value);
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
        strlen(builder->oauth_signature_method.value),
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
    int written = snprintf(timestamp, sizeof timestamp, "%ld", (long)now);
    builder->oauth_timestamp.value = oauth_strdup(timestamp);
    curl_encode(builder->oauth_timestamp.value, written,
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
        strlen(builder->oauth_version.value),
        &builder->oauth_version.encoded_value);
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
    const Param *lst[] = {

    }
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
set_consumer_key(Builder* builder, const char* key) {
    builder->oauth_consumer_key.value = oauth_strdup(key);

    curl_encode(builder->oauth_consumer_key.value,
        strlen(builder->oauth_consumer_key.value),
        &builder->oauth_consumer_key.encoded_value);
}

/**
 * @brief      Sets the consumer secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The secret
 */
void 
set_consumer_secret(Builder* builder, const char* key) {
    builder->rest[CONSUMER_SECRET] = oauth_strdup(key);
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
set_token(Builder* builder, const char* key) {
    builder->oauth_token.value = oauth_strdup(key);

    curl_encode(builder->oauth_token.value,
        strlen(builder->oauth_token.value),
        &builder->oauth_token.encoded_value);
}

/**
 * @brief      Sets the token secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The token secret
 */
void 
set_token_secret(Builder* builder, const char* key) {
    builder->rest[TOKEN_SECRET] = oauth_strdup(key);
}

/**
 * @brief      Sets the url method.
 *
 * @param      builder  The builder
 * @param[in]  key      The url method
 */
void 
set_url_method(Builder* builder, const char* key) {
    builder->rest[METHOD] = oauth_strdup(key);
}

/**
 * @brief      Sets the url.
 *
 * @param      builder  The builder
 * @param[in]  key      The url
 */
void
set_url(Builder* builder, const char* key) {
    builder->rest[URL] = oauth_strdup(key);
}

/**
 * @brief      Sets the url parameters.
 *
 * @param      builder  The builder
 * @param      key      The array of parameters
 * @param[in]  len      The length of the array
 */
void
set_url_params(Builder* builder, const char** key, int len) {
    /*builder->rest[URL_PARAMS] = oauth_strdup(key);*/
}

/**
 * @brief      Creates a new builder object
 *
 * @return     a builder for collecting the required parameters
 */
Builder*
new_oauth_builder( void ) {
    Builder* builder = malloc(sizeof (Builder));
    Builder temp = { {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL}, {NULL, NULL, NULL, NULL, NULL}
    };

    temp.oauth_consumer_key.name = oauth_strdup("oauth_consumer_key");
    temp.oauth_nonce.name = oauth_strdup("oauth_nonce");
    temp.oauth_signature.name = oauth_strdup("oauth_signature");
    temp.oauth_signature_method.name = oauth_strdup("oauth_signature_method");
    temp.oauth_timestamp.name = oauth_strdup("oauth_timestamp");
    temp.oauth_token.name = oauth_strdup("oauth_token");
    temp.oauth_version.name = oauth_strdup("oauth_version");

    curl_encode(temp.oauth_consumer_key.name,
        strlen(temp.oauth_consumer_key.name),
        &temp.oauth_consumer_key.encoded_name);

    curl_encode(temp.oauth_nonce.name,
        strlen(temp.oauth_nonce.name),
        &temp.oauth_nonce.encoded_name);

    curl_encode(temp.oauth_signature.name,
        strlen(temp.oauth_signature.name),
        &temp.oauth_signature.encoded_name);

    curl_encode(temp.oauth_signature_method.name,
        strlen(temp.oauth_signature_method.name),
        &temp.oauth_signature_method.encoded_name);

    curl_encode(temp.oauth_timestamp.name,
        strlen(temp.oauth_timestamp.name),
        &temp.oauth_timestamp.encoded_name);

    curl_encode(temp.oauth_token.name,
        strlen(temp.oauth_token.name),
        &temp.oauth_token.encoded_name);

    curl_encode(temp.oauth_version.name,
        strlen(temp.oauth_version.name),
        &temp.oauth_version.encoded_name);

    memcpy(builder, &temp, sizeof (Builder));

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

        free (*builder);

        // Explicitly set the pointer to null
        *builder = NULL;
        if (--BUILDER_REF_COUNT == 0) {
            curl_easy_cleanup(curl);
        }
    }
}

/**
 * @brief      Gets the header string.
 *
 * @param[in]  builder  The builder with all the required parameters
 *
 * @return     The header string.
 */
const char*
get_header_string(const Builder* builder) {
    set_nonce(builder);
    set_signature_method(builder);
    set_timestamp(builder);
    set_oauth_version(builder);

    /* Done last in order to have the values needed*/
    set_signature(builder);

    /* signature method */

    return NULL;
}
