# Build the liboauthsign and liboauthsigntw

add_library(oauthsign STATIC liboauthsign.c)
add_library(oauthsigntw_static liboauthsigntw.c ${PROJECT_SOURCE_DIR}/logger.c)
target_link_libraries(oauthsigntw_static crypto curl oauthsign)
