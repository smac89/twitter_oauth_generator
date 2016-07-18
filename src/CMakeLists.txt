set(CORELIBS crypto curl oauthsign)

set(SOURCE_FILES
        oauth_sign.c
        ${PROJECT_SOURCE_DIR}/lib/liboauthsigntw.c
        ${PROJECT_SOURCE_DIR}/lib/liboauthsign.c
        ${PROJECT_SOURCE_DIR}/util/logger.c)

add_executable(oauth_sign ${SOURCE_FILES})
target_link_libraries(oauth_sign ${CORELIBS})