# https://cmake.org/Wiki/CMake/Tutorials/Exporting_and_Importing_Targets
# Find and add the cmocka library
find_library(CMOCKA_LIBRARY NAMES cmocka)
add_library(cmocka SHARED IMPORTED)
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION "${CMOCKA_LIBRARY}")

# Create and link the testing file to cmocka
add_executable(tw_oauthsign_test liboauthsign_test.c)
target_link_libraries(tw_oauthsign_test oauthsign cmocka)

# Add this as a test for ctest
add_test(TEST_LIB_OAUTH tw_oauthsign_test)
