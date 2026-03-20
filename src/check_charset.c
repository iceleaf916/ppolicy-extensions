#include "ppolicy_ext.h"
#include <ctype.h>
#include <string.h>

static int has_uppercase(const char* password) {
    while (*password) {
        if (isupper((unsigned char)*password)) return 1;
        password++;
    }
    return 0;
}

static int has_lowercase(const char* password) {
    while (*password) {
        if (islower((unsigned char)*password)) return 1;
        password++;
    }
    return 0;
}

static int has_digit(const char* password) {
    while (*password) {
        if (isdigit((unsigned char)*password)) return 1;
        password++;
    }
    return 0;
}

static int has_special(const char* password) {
    while (*password) {
        if (!isalnum((unsigned char)*password)) return 1;
        password++;
    }
    return 0;
}

pwd_check_result_t ppolicy_check_charset(const char* password, int char_set) {
    if (char_set & 1) {  /* 需要大写 */
        if (!has_uppercase(password)) return PWD_CHECK_CHAR_SET_UPPER;
    }
    if (char_set & 2) {  /* 需要小写 */
        if (!has_lowercase(password)) return PWD_CHECK_CHAR_SET_LOWER;
    }
    if (char_set & 4) {  /* 需要数字 */
        if (!has_digit(password)) return PWD_CHECK_CHAR_SET_DIGIT;
    }
    if (char_set & 8) {  /* 需要特殊字符 */
        if (!has_special(password)) return PWD_CHECK_CHAR_SET_SPECIAL;
    }
    return PWD_CHECK_OK;
}
