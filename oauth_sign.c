/* oauth_sign.c - sign an OAuth request
**
** Given a method, URL, consumer key & secret, and token & secret, this
** program returns the OAuth signature.  See:
**   http://tools.ietf.org/html/rfc5849#section-3.1
** The signature is generated using HMAC-SHA1, as specified in:
**   http://tools.ietf.org/html/rfc5849#section-3.4.2
** The protocol parameters are returned as an Authorization header
** value, as specified in:
**   http://tools.ietf.org/html/rfc5849#section-3.5.1
**
** Copyright © 2010,2012 by Jef Poskanzer <jef@mail.acme.com>.
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
#include <stdarg.h>
#include <sysexits.h>
#include "logger.h"
// #include "liboauthsign.h"


static void usage( void );
static int check_method( const char *method );
static char* program_name;

int main( int argc, char** argv ) {
    int argn;
    int query_mode;
    int show_sbs;
    char* consumer_key;
    char* consumer_key_secret;
    char* token;
    char* token_secret;
    char* method;
    char* url;
    int paramc;
    char** paramv;
    char* result;

    /* Figure out the program's name. */
    {
        program_name = strrchr( argv[0], '/' );
        if ( program_name != (char*) 0 )
            ++program_name;
        else
            program_name = argv[0];
    }

    /* Get flags. */
    argn = 1;
    query_mode = 0;
    show_sbs = 0;
    while ( argn < argc && argv[argn][0] == '-' && argv[argn][1] != '\0' ) {
    	if ( strcmp( argv[argn], "-q" ) == 0 )
    	    query_mode = 1;
    	else if ( strcmp( argv[argn], "-b" ) == 0 )
    	    show_sbs = 1;
    	else
    	    usage();
    	++argn;
	}

    /* Get args. */
    if ( argc - argn < 6 )
	   usage();

    consumer_key = argv[argn++];
    consumer_key_secret = argv[argn++];
    token = argv[argn++];
    token_secret = argv[argn++];
    method = argv[argn++];
    url = argv[argn++];
    paramc = argc - argn;
    paramv = &(argv[argn]);

    if ( query_mode && paramc > 0 ) {
    	(void) fprintf( stderr, "%s: -q doesn't work with extra POST parameters\n", program_name );
    	exit( EX_USAGE );
	}

    if ( strcmp( method, "GET" ) != 0 && strcmp( method, "HEAD" ) != 0 && strcmp( method, "POST" ) != 0 ) {
    	(void) fprintf( stderr, "%s: method must be GET, HEAD, or POST\n", program_name );
    	exit( EX_USAGE );
	}

 //    if ( show_sbs )
 //    	oauth_show_sbs();
 //        result = oauth_sign( query_mode, consumer_key, consumer_key_secret, token, token_secret, method, url, paramc, paramv );

 //    if ( result == (char*) 0 ) {
 //    	(void) fprintf( stderr, "%s: signing failed\n", program_name );
 //    	exit( EX_SOFTWARE );
	// }

 //    (void) printf( "%s\n", result );
 //    free( result );

    exit( EX_OK );
}

static void check_method( const char *method ) {
    static const char* methods[] = {
        "GET", "POST", "DELETE",
        "PUT", "HEAD"
    };

    int valid = 0, size = sizeof methods, cnt = 0;
    char *mptr = NULL;
    for (mptr = methods[cnt++]; cnt < size; mptr = methods[cnt++]) {
        if (strcmp(method, mptr) == 0) {
            valid = 1;
            break;
        }
    }

    if (valid != 1) {
        e_log()
        (void) fprintf( stderr, "%s: -q doesn't work with extra POST parameters\n", program_name );
        exit( EX_USAGE );
    }

    return valid;
}

static void usage( void ) {
    (void) fprintf( stderr, "usage:  %s [-q|-b] consumer_key consumer_key_secret token token_secret method url [name=value ...]\n", program_name );
    exit( EX_USAGE );
}

// char *b64 = malloc(bptr->length);
// snprintf(format, sizeof format, "%%.%zus", bptr->length)
// 
// #include <openssl/rand.h>
// #include <openssl/bio.h>
// #include <openssl/evp.h>
// #include <openssl/buffer.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// static BUF_MEM*
// base64_bytes(int size) {
//     char *buf = malloc(size + 1), format[20];
//     int chunk;
//     BIO *b64, *out;
//     BUF_MEM *bptr;

//     // Create a base64 filter/sink
//     if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
//         return NULL;
//     }

//     // Create a memory source
//     if ((out = BIO_new(BIO_s_mem())) == NULL) {
//         return NULL;
//     }

//     // Chain them
//     out = BIO_push(b64, out);
//     //Ignore newlines - write everything in one line
//     BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);

//     // Generate random bytes
//     if (!RAND_bytes(buf, size)) {
//         return NULL;
//     }

//     BIO_write(out, buf, size);
//     BIO_flush(out);
//     BIO_get_mem_ptr(out, &bptr);
//     BIO_set_close(out, BIO_NOCLOSE);
//     BIO_free_all(out);

//     return bptr;
// }

// int main() {
//     BUF_MEM *mem = base64_bytes(32);
//     if (mem != NULL) {
//         char format[100];
//         snprintf(format, sizeof format, "The size is %1$zu\n%%.%1$zus\n\n", mem->length);
//         printf(format, mem->data);
//     }
    
//     // unsigned char buffer[33] = {}, *base64EncodeOutput;
//     // int ret = RAND_bytes(buffer, sizeof buffer);

//     // (void)Base64Encode(buffer, &base64EncodeOutput);
//     // (void)printf("Return value of the operation was: %d\n%45s\n", ret, base64EncodeOutput);


//     return EXIT_SUCCESS;
// }
