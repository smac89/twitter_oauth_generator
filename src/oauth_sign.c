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
** Copyright � 2010,2012 by Jef Poskanzer <jef@mail.acme.com>.
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
#include <ctype.h>
#include <sysexits.h>
#include "logger.h"
#include "liboauthsign.h"


static void usage(void);

static int check_method(char *method);

static char *program_name;

int main(int argc, char **argv) {
    int argn;
    int query_mode;
    int show_sbs;
    char *consumer_key;
    char *consumer_key_secret;
    char *token;
    char *token_secret;
    char *method;
    char *url;
    int paramc;
    char **paramv;
    char *result;

    /* Figure out the program's name. */
    {
        program_name = strrchr(argv[0], '/');
        if (program_name != (char *) 0)
            ++program_name;
        else
            program_name = argv[0];
    }

    /* Get flags. */
    argn = 1;
    query_mode = 0;
    show_sbs = 0;
    while (argn < argc && argv[argn][0] == '-' && argv[argn][1] != '\0') {
        if (strcmp(argv[argn], "-q") == 0)
            query_mode = 1;
        else if (strcmp(argv[argn], "-b") == 0)
            show_sbs = 1;
        else
            usage();
        ++argn;
    }

    /* Get args. */
    if (argc - argn < 6) {
        usage();
    }

    consumer_key = argv[argn++];
    consumer_key_secret = argv[argn++];
    token = argv[argn++];
    token_secret = argv[argn++];
    method = argv[argn++];

    /***********************************************/
    /*char *url = strtok(oauth_strdup(key), "?#");*/
    url = argv[argn++];
    /***********************************************/

    paramc = argc - argn;
    paramv = &(argv[argn]);

    if (query_mode && paramc > 0) {
        e_log("%s: -q doesn't work with extra POST parameters\n", program_name);
        exit(EX_USAGE);
    }

    if (check_method(method) != 1) {
        e_log("%s: method must be GET, POST, DELETE, PUT, or HEAD\n", program_name);
        exit(EX_USAGE);
    }

    if (show_sbs) {
        oauth_show_sbs();
    }

    /*
        Builder *b = new_oauth_builder();
        set_consumer_key(b, "Hello");
        destroy_builder(&b);
     */

    result = oauth_sign(query_mode, consumer_key, consumer_key_secret, token, token_secret, method, url, paramc,
                        paramv);

    if (result == (char *) 0) {
        e_log("%s: signing failed\n", program_name);
        exit(EX_SOFTWARE);
    }

    (void) printf("%s\n", result);
    free(result);

    exit(EX_OK);
}

static int check_method(char *method) {
    static const char *methods[] = {
            "GET", "POST", "DELETE",
            "PUT", "HEAD"
    };

    int valid = 0, size = sizeof methods, cnt;
    char *up = method;

    while (*up) {
        *up = toupper(*up);
        ++up;
    }

    for (cnt = 0; cnt < size; cnt++) {
        if (strcmp(method, methods[cnt]) == 0) {
            valid = 1;
            break;
        }
    }

    return valid;
}

static void usage(void) {
    e_log("usage:  %s [-q|-b] "
                  "<consumer_key> <consumer_key_secret> "
                  "<token> <token_secret> <method< <url> "
                  "[name=value ...]\n", program_name);
    exit(EX_USAGE);
}
