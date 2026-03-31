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

int main() {
    test_ppolicy_trim();
    test_ppolicy_strcasestr();
    printf("All utils tests passed!\n");
    return 0;
}
