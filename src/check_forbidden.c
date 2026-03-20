#include "ppolicy_ext.h"
#include <string.h>
#include <stdlib.h>

static char* ppolicy_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* copy = malloc(len);
    if (copy) memcpy(copy, s, len);
    return copy;
}

pwd_check_result_t ppolicy_check_forbidden(const char* password, const char* forbidden_list) {
    if (!forbidden_list || !password || *forbidden_list == '\0') {
        return PWD_CHECK_OK;
    }

    char* list_copy = ppolicy_strdup(forbidden_list);
    if (!list_copy) return PWD_CHECK_OK;

    char* token = strtok(list_copy, ",");
    while (token) {
        ppolicy_trim(token);
        if (*token && ppolicy_strcasestr(password, token)) {
            free(list_copy);
            return PWD_CHECK_FORBIDDEN_STRING;
        }
        token = strtok(NULL, ",");
    }

    free(list_copy);
    return PWD_CHECK_OK;
}
