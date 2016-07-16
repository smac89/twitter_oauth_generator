cmake_minimum_required(VERSION 3.5)
project(oauth_sign)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O -ansi -pedantic -g -U__STRICT_ANSI__ \
-Wall -Wextra -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast \
-Wno-missing-field-initializers -Wno-long-long -Wswitch-default -Wshadow -Wunreachable-code \
-Wold-style-definition")

set(SOURCE_FILES
        liboauthsign.c
        liboauthsigntw.c
        logger.c
        oauth_sign.c)

# Build the liboauthsign
add_library(oauthsign STATIC liboauthsign.c)

set(CORELIBS crypto curl oauthsign)

add_executable(oauth_sign ${SOURCE_FILES})
target_link_libraries(oauth_sign ${CORELIBS})