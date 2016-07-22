
#include <stddef.h>
#include <cmocka.h>


static void test(void **state) {
//    https://git.cryptomilk.org/projects/cmocka.git/refs/
    assert_int_equal(3, 3);
    assert_int_not_equal(3, 4);
}

int main(void) {
    const UnitTest tests[] = {
            unit_test(test)
    };
    return run_tests(tests);
}
