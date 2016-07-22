set(CORELIBS crypto curl oauthsign)

set(SOURCE_FILES
        oauth_sign.c
        ${PROJECT_SOURCE_DIR}/liboauthsign.tw/liboauthsigntw.c
        ${PROJECT_SOURCE_DIR}/liboauthsign.tw/liboauthsign.c
        ${PROJECT_SOURCE_DIR}/tools/logger.c)

add_executable(oauth_sign ${SOURCE_FILES})
target_link_libraries(oauth_sign ${CORELIBS})