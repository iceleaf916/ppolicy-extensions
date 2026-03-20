#include "ppolicy_ext.h"

/**
 * 执行所有扩展密码检查
 * 按顺序执行，遇到第一个失败立即返回
 */
int ppolicy_ext_check_password(
    ppolicy_ext_ctx_t*       ctx,
    pwd_user_context_t*     user,
    pwd_policy_extension_t* policy
) {
    pwd_check_result_t result;
    const char* password = user->password;
    int length = user->password_len;

    (void)ctx;  /* 未使用的上下文参数 */

    /* 1. 检查最大长度 */
    if (policy->pwd_max_length > 0) {
        result = ppolicy_check_max_length(password, length, policy->pwd_max_length);
        if (result != PWD_CHECK_OK) return result;
    }

    /* 2. 检查字符集 */
    if (policy->pwd_char_set > 0) {
        result = ppolicy_check_charset(password, policy->pwd_char_set);
        if (result != PWD_CHECK_OK) return result;
    }

    /* 3. 检查用户名包含 */
    if (policy->pwd_no_user_check) {
        result = ppolicy_check_no_user(user, password);
        if (result != PWD_CHECK_OK) return result;
    }

    /* 4. 检查黑名单 */
    if (policy->pwd_forbidden_strings && *policy->pwd_forbidden_strings) {
        result = ppolicy_check_forbidden(password, policy->pwd_forbidden_strings);
        if (result != PWD_CHECK_OK) return result;
    }

    return LDAP_SUCCESS;
}
