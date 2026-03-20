#include "ppolicy_ext.h"

/**
 * 检查密码是否超过最大长度
 */
pwd_check_result_t ppolicy_check_max_length(
    const char* password,
    int         length,
    int         max_length
) {
    (void)password;  /* 未使用，保留参数以保持 API 一致性 */
    if (max_length > 0 && length > max_length) {
        return PWD_CHECK_MAX_LENGTH;
    }
    return PWD_CHECK_OK;
}
