#include "ppolicy_ext.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

const char* ppolicy_check_result_to_string(pwd_check_result_t result) {
    static const char* messages[] = {
        [PWD_CHECK_OK]                    = "Success",
        [PWD_CHECK_MAX_LENGTH]           = "Password exceeds maximum length",
        [PWD_CHECK_CHAR_SET_UPPER]       = "Password must contain uppercase letter",
        [PWD_CHECK_CHAR_SET_LOWER]       = "Password must contain lowercase letter",
        [PWD_CHECK_CHAR_SET_DIGIT]       = "Password must contain digit",
        [PWD_CHECK_CHAR_SET_SPECIAL]     = "Password must contain special character",
        [PWD_CHECK_USER_IN_PASSWORD]      = "Password must not contain user name",
        [PWD_CHECK_FORBIDDEN_STRING]     = "Password contains forbidden string"
    };
    if (result < 0 || result > 7) return "Unknown error";
    return messages[result];
}

char* ppolicy_trim(char* str) {
    if (str == NULL) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

int ppolicy_strcasestr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return 0;
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return 0;
    size_t haystack_len = strlen(haystack);
    if (haystack_len < needle_len) return 0;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (strncasecmp(haystack + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

int ppolicy_parse_string_list(const char* input, char** output, int max_count) {
    if (!input || !output || max_count <= 0) return 0;

    char* copy = strdup(input);
    if (!copy) return 0;

    int count = 0;
    char* token = strtok(copy, ",");
    while (token && count < max_count) {
        /* 对每个 token 分别 trim */
        char* trimmed = ppolicy_trim(token);
        output[count] = strdup(trimmed);
        if (output[count]) count++;
        token = strtok(NULL, ",");
    }

    free(copy);
    return count;
}

void ppolicy_free_string_list(char** list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        free(list[i]);
        list[i] = NULL;
    }
}

void ppolicy_format_error(pwd_check_result_t result, char* buf, size_t buf_size, ...) {
    snprintf(buf, buf_size, "%s", ppolicy_check_result_to_string(result));
}
