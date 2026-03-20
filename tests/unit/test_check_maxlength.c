#include <stdio.h>
#include <assert.h>
#include "ppolicy_ext.h"

void test_check_max_length_ok() {
    assert(ppolicy_check_max_length("password123", 11, 64) == PWD_CHECK_OK);
    assert(ppolicy_check_max_length("pass", 4, 10) == PWD_CHECK_OK);
}

void test_check_max_length_fail() {
    assert(ppolicy_check_max_length("password123456789", 17, 10) == PWD_CHECK_MAX_LENGTH);
    assert(ppolicy_check_max_length("thisisalongpassword", 18, 16) == PWD_CHECK_MAX_LENGTH);
}

void test_check_max_length_no_limit() {
    assert(ppolicy_check_max_length("anystring", 9, 0) == PWD_CHECK_OK);
}

int main() {
    test_check_max_length_ok();
    test_check_max_length_fail();
    test_check_max_length_no_limit();
    printf("All maxlength tests passed!\n");
    return 0;
}
