#include <stdio.h>
#include <assert.h>
#include "ppolicy_ext.h"

void test_check_charset_upper() {
    /* Bit 0 = 1: 需要大写 */
    assert(ppolicy_check_charset("Password", 1) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("password", 1) == PWD_CHECK_CHAR_SET_UPPER);
}

void test_check_charset_lower() {
    /* Bit 1 = 2: 需要小写 */
    assert(ppolicy_check_charset("password", 2) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("PASSWORD", 2) == PWD_CHECK_CHAR_SET_LOWER);
}

void test_check_charset_digit() {
    /* Bit 2 = 4: 需要数字 */
    assert(ppolicy_check_charset("Pass123", 4) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("Password", 4) == PWD_CHECK_CHAR_SET_DIGIT);
}

void test_check_charset_special() {
    /* Bit 3 = 8: 需要特殊字符 */
    assert(ppolicy_check_charset("Password!", 8) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("Password", 8) == PWD_CHECK_CHAR_SET_SPECIAL);
}

void test_check_charset_combined() {
    /* Bit 0+1+2 = 7: 大写+小写+数字 */
    assert(ppolicy_check_charset("Password123", 7) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("password123", 7) == PWD_CHECK_CHAR_SET_UPPER);
    assert(ppolicy_check_charset("PASSWORD123", 7) == PWD_CHECK_CHAR_SET_LOWER);
    assert(ppolicy_check_charset("PasswordABC", 7) == PWD_CHECK_CHAR_SET_DIGIT);
}

int main() {
    test_check_charset_upper();
    test_check_charset_lower();
    test_check_charset_digit();
    test_check_charset_special();
    test_check_charset_combined();
    printf("All charset tests passed!\n");
    return 0;
}
