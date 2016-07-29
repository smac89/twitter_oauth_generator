set(CORELIBS crypto curl oauthsign)

set(SOURCE_FILES
        oauth_sign.c
        ${PROJECT_SOURCE_DIR}/liboauthsign.c
        ${PROJECT_SOURCE_DIR}/logger.c)

add_executable(oauth_sign ${SOURCE_FILES})
target_link_libraries(oauth_sign ${CORELIBS})
