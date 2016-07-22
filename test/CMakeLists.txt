# Find and add the cmocka library
find_library(CMOCKA_LIBRARY NAMES cmocka)
add_library(cmocka SHARED IMPORTED)
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION "${CMOCKA_LIBRARY}")

# Create and link the testing file to cmocka
add_executable(oauthsigntwtest liboauthsign_test.c)
target_link_libraries(oauthsigntwtest oauthsign cmocka)

# Add this as a test for ctest
add_test(TEST_LIB_OAUTH oauthsigntwtest)