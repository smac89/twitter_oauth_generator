cmake_minimum_required(VERSION 2.8)
project(oauth_sign)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O -std=c99 -pedantic -g -U__STRICT_ANSI__ -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers -Wno-long-long -Wswitch-default -Wshadow ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunreachable-code -Wold-style-definition")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")

add_library(oauthsign liboauthsign.c logger.c)
target_link_libraries(oauthsign crypto curl)

include_directories(include)

enable_testing()

add_subdirectory(src)
add_subdirectory(test)
