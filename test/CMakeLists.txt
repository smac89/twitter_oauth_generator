# https://cmake.org/Wiki/CMake/Tutorials/Exporting_and_Importing_Targets
# Find and add the cmocka library
find_library(CMOCKA_LIBRARY NAMES cmocka)
add_library(cmocka SHARED IMPORTED)
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION "${CMOCKA_LIBRARY}")

add_library(oauthsigntw ${PROJECT_SOURCE_DIR}/liboauthsign.tw/liboauthsigntw.c ${PROJECT_SOURCE_DIR}/logger.c)
target_link_libraries(oauthsigntw crypto curl oauthsign)

# Create and link the testing file to cmocka
add_executable(oauthsigntwtest liboauthsign_test.c)
target_link_libraries(oauthsigntwtest oauthsigntw cmocka)

# Add this as a test for ctest
add_test(TEST_LIB_OAUTH oauthsigntwtest)
