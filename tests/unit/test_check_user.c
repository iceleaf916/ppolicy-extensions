#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "ppolicy_ext.h"

void test_check_no_user_ok() {
    pwd_user_context_t user = {
        .uid = "john",
        .cn = "John Doe",
        .sn = "Doe",
        .given_name = "John",
        .password = "SecurePass123",
        .password_len = 12
    };
    assert(ppolicy_check_no_user(&user, "SecurePass123") == PWD_CHECK_OK);
}

void test_check_no_user_fail() {
    pwd_user_context_t user = {
        .uid = "john",
        .cn = "John Doe",
        .sn = "Doe",
        .given_name = "John",
        .password = "johnPassword123",
        .password_len = 15
    };
    assert(ppolicy_check_no_user(&user, "johnPassword123") == PWD_CHECK_USER_IN_PASSWORD);
}

int main() {
    test_check_no_user_ok();
    test_check_no_user_fail();
    printf("All user check tests passed!\n");
    return 0;
}
