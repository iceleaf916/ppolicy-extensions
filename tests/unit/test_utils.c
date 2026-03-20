#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../../include/ppolicy_ext.h"

void test_ppolicy_trim() {
    char s1[] = "  hello  ";
    char s2[] = "hello";
    char s3[] = "";

    assert(strcmp(ppolicy_trim(s1), "hello") == 0);
    assert(strcmp(ppolicy_trim(s2), "hello") == 0);
    assert(strcmp(ppolicy_trim(s3), "") == 0);
}

void test_ppolicy_strcasestr() {
    assert(ppolicy_strcasestr("HelloWorld", "world") == 1);
    assert(ppolicy_strcasestr("HelloWorld", "WORLD") == 1);
    assert(ppolicy_strcasestr("HelloWorld", "foo") == 0);
    assert(ppolicy_strcasestr("", "foo") == 0);
    assert(ppolicy_strcasestr("Hello", "") == 0);
}

void test_ppolicy_parse_string_list() {
    char* output[10];
    int count;

    count = ppolicy_parse_string_list("a,b,c", output, 10);
    assert(count == 3);
    assert(strcmp(output[0], "a") == 0);
    assert(strcmp(output[1], "b") == 0);
    assert(strcmp(output[2], "c") == 0);

    /* 释放内存 */
    ppolicy_free_string_list(output, count);

    /* 验证 trim 功能 */
    count = ppolicy_parse_string_list(" a , b , c ", output, 10);
    assert(count == 3);
    assert(strcmp(output[0], "a") == 0);

    /* 释放内存 */
    ppolicy_free_string_list(output, count);
}

int main() {
    test_ppolicy_trim();
    test_ppolicy_strcasestr();
    test_ppolicy_parse_string_list();
    printf("All utils tests passed!\n");
    return 0;
}
