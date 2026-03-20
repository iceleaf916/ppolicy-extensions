#include "ppolicy_ext.h"
#include <string.h>

pwd_check_result_t ppolicy_check_no_user(pwd_user_context_t* user, const char* password) {
    if (user->uid && ppolicy_strcasestr(password, user->uid)) {
        return PWD_CHECK_USER_IN_PASSWORD;
    }
    if (user->cn && ppolicy_strcasestr(password, user->cn)) {
        return PWD_CHECK_USER_IN_PASSWORD;
    }
    if (user->sn && ppolicy_strcasestr(password, user->sn)) {
        return PWD_CHECK_USER_IN_PASSWORD;
    }
    if (user->given_name && ppolicy_strcasestr(password, user->given_name)) {
        return PWD_CHECK_USER_IN_PASSWORD;
    }
    return PWD_CHECK_OK;
}
