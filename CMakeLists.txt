cmake_minimum_required(VERSION 3.5)
project(oauth_sign)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O -ansi -pedantic -g -U__STRICT_ANSI__ \
-Wall -Wextra -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast \
-Wno-missing-field-initializers -Wno-long-long -Wswitch-default -Wshadow -Wunreachable-code \
-Wold-style-definition")

include_directories(include)

add_subdirectory(src)
add_subdirectory(lib)
add_subdirectory(util)

# This is a library to help with testing
# https://github.com/ThrowTheSwitch/Unity/tree/master/src