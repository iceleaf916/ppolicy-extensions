#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "ppolicy_ext.h"

void test_check_forbidden_ok() {
    assert(ppolicy_check_forbidden("MySecurePass123", "weak,password,admin") == PWD_CHECK_OK);
}

void test_check_forbidden_fail() {
    assert(ppolicy_check_forbidden("Password123", "weak,password,admin") == PWD_CHECK_FORBIDDEN_STRING);
    assert(ppolicy_check_forbidden("AdminPass", "weak,password,admin") == PWD_CHECK_FORBIDDEN_STRING);
}

void test_check_forbidden_empty() {
    assert(ppolicy_check_forbidden("AnyPassword", "") == PWD_CHECK_OK);
    assert(ppolicy_check_forbidden("AnyPassword", NULL) == PWD_CHECK_OK);
}

int main() {
    test_check_forbidden_ok();
    test_check_forbidden_fail();
    test_check_forbidden_empty();
    printf("All forbidden tests passed!\n");
    return 0;
}
