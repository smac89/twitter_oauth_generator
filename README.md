# twitter_oauth_generator

- Helper to generate Authorization headers for Twitter oauth api requests
- Originally derived from http://acme.com/software/oauth_sign/

[![Licence](https://img.shields.io/badge/Licence-MIT-blue.svg)](https://github.com/smac89/twitter_oauth_generator/blob/master/LICENSE) <a id="ci" href="https://circleci.com/gh/smac89/twitter_oauth_generator"><img src="https://circleci.com/gh/smac89/twitter_oauth_generator.svg?style=svg&circle-token=f2c9731e54d3e36d83d3c4cf9ae5a5d6a130acd3"/></a>

---

                oauth_sign - generate an OAuth signature

OAuth is a three-party authorization protocol described in RFC5849.
Oauth_sign generates a signature header to use when making an OAuth
request.

To use it, you supply the four cryptographic cookies and the method
and URL of the request.  If it's a POST request with extra
parameters, you have to give those too.  Oauth_sign puts all this
together and makes the signature string.  The signature is generated
using HMAC-SHA1 as specified in RFC section 3.4.2, and is returned as
an Authorization header value as specified in RFC section 3.5.1.  This
header can then be used in an HTTP request via, for example, the
-h flag in http_get(1) and http_post(1) or the -H flag in curl(1).

The signature may also be generated as query parameters, as specified
in RFC section 3.5.3, by using the -q flag.

The signature generation code is also available as a C function,
if you want to link it into your code directly.

See the manual entry for more details.

Files in this distribution:

    ├── include
    │   ├── liboauthsign.h
    │   └── logger.h
    ├── src
    │   ├── CMakeLists.txt
    │   └── oauth_sign.c
    ├── test
    │   ├── CMakeLists.txt
    │   └── liboauthsign_test.c
    ├── CMakeLists.txt
    ├── configure.sh
    ├── liboauthsign.c
    ├── LICENSE
    ├── logger.c
    ├── oauth_sign.1
    └── README.md

To build:
- `chmod configure`
- `./configure`
