cmake_minimum_required(VERSION 3.5)
project(oauth_sign)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O -std=c99 -pedantic -g -U__STRICT_ANSI__ \
-Wall -Wextra -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast \
-Wno-missing-field-initializers -Wno-long-long -Wswitch-default -Wshadow -Wunreachable-code \
-Wold-style-definition")

add_library(oauthsign STATIC liboauthsign.c)
add_library(oauthsigntw_static liboauthsigntw.c logger.c)
target_link_libraries(oauthsigntw_static crypto curl oauthsign)

include_directories(include)

enable_testing()

add_subdirectory(src)
add_subdirectory(test)
