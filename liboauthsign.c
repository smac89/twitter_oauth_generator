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
#define INIT_BUILDER_PATTERN()

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

/**/
struct OauthBuilder {
    Param oauth_consumer_key;
    Param oauth_signature;
    Param oauth_signature_method;
    Param oauth_timestamp;
    Param oauth_token;
    Param oauth_version;
};

static CURL* curl = curl_easy_init();
static int show_sbs = 0;

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

    #if defined(__FreeBSD__)
        srandomdev();
    #else /* __FreeBSD__ */
        srandom( (int) time( (time_t*) 0 ) ^ getpid() );
    #endif /* __FreeBSD__ */

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
    bytes = strdup(bptr->data);

    /*Cleanup*/
    BIO_set_close(mem, BIO_CLOSE);
    BIO_free_all(mem);
    if (freesrc) 
        free(src);

    return bytes;
}

static void
curl_encode(const char* in, size_t length, char **out) {
    char *encode = curl_easy_escape(curl, in, length);
    *out = strdup(encode);
    curl_free(encode);
}

static void
curl_decode(const char* in, size_t length, char **out) {
    int len;
    char *decode = curl_easy_unescape(curl, in, length, &len);
    *out = strdup(decode);
    curl_free(decode);
}

static void 
set_key(Builder* builder, const char* key) {
    builder->oauth_consumer_key.value = strdup(key);
}

Builder*
new_oauth_builder() {
    Builder* base = malloc(sizeof (Builder));
    set_consumer_key = set_key;
    return base;
}

void destroy_builder(Builder *builder) {

}

const char*
get_signature(const Builder* builder) {
    return NULL;
}
