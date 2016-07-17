cmake_minimum_required(VERSION 3.5)
project(oauth_sign)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O -ansi -pedantic -g -U__STRICT_ANSI__ \
-Wall -Wextra -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast \
-Wno-missing-field-initializers -Wno-long-long -Wswitch-default -Wshadow -Wunreachable-code \
-Wold-style-definition")

set(CORELIBS crypto curl oauthsign)
set(SOURCE_FILES
        src/liboauthsigntw.c
        src/liboauthsign.c
        src/logger.c
        src/oauth_sign.c)

# Build the liboauthsign
add_library(oauthsign STATIC src/liboauthsign.c)

add_executable(oauth_sign ${SOURCE_FILES})
target_link_libraries(oauth_sign ${CORELIBS})

# This is a library to help with testing
# https://github.com/ThrowTheSwitch/Unity/tree/master/src