#ifndef PPOLICY_EXT_H
#define PPOLICY_EXT_H

#include <ldap.h>
#include <sys/types.h>

/**
 * 模块上下文
 */
typedef struct ppolicy_ext_ctx {
    void*               module_handle;      // 模块句柄
    int                 cache_ttl;         // 缓存 TTL（秒）
    time_t              last_cleanup;       // 最后清理时间
} ppolicy_ext_ctx_t;

/**
 * 扩展密码策略配置
 */
typedef struct pwd_policy_extension {
    int         pwd_max_length;        // 密码最大长度，0表示不限制
    int         pwd_char_set;          // 字符集选项位标志
    int         pwd_no_user_check;     // 是否检查用户名包含（非0=是）
    char*       pwd_forbidden_strings;  // 黑名单字符串（逗号分隔）
    time_t      last_refresh;          // 最后刷新时间
} pwd_policy_extension_t;

/**
 * 用户上下文信息
 */
typedef struct pwd_user_context {
    char*       dn;                     // 用户 DN
    char*       uid;                    // 用户名 (uid)
    char*       cn;                      // 通用名 (cn)
    char*       sn;                      // 姓氏 (sn)
    char*       given_name;             // 名 (givenName)
    char*       password;                // 新密码（待验证）
    int         password_len;           // 密码长度
} pwd_user_context_t;

/**
 * 检查结果枚举
 */
typedef enum pwd_check_result {
    PWD_CHECK_OK = 0,
    PWD_CHECK_MAX_LENGTH = 1,
    PWD_CHECK_CHAR_SET_UPPER = 2,
    PWD_CHECK_CHAR_SET_LOWER = 3,
    PWD_CHECK_CHAR_SET_DIGIT = 4,
    PWD_CHECK_CHAR_SET_SPECIAL = 5,
    PWD_CHECK_USER_IN_PASSWORD = 6,
    PWD_CHECK_FORBIDDEN_STRING = 7
} pwd_check_result_t;

/* === API 声明 === */

/* 模块初始化/销毁 */
int ppolicy_ext_init(ppolicy_ext_ctx_t** ctx);
void ppolicy_ext_destroy(ppolicy_ext_ctx_t* ctx);

/* 密码检查主函数 */
int ppolicy_ext_check_password(
    ppolicy_ext_ctx_t*      ctx,
    pwd_user_context_t*     user,
    pwd_policy_extension_t* policy
);

/* 策略加载 */
int ppolicy_ext_load_policy(
    LDAP*                   ld,
    const char*             policy_dn,
    pwd_policy_extension_t* policy
);

int ppolicy_ext_get_policy_dn(
    LDAP*   ld,
    const char* user_dn,
    char*   policy_dn_buf,
    size_t  buf_size
);

/* 工具函数 */
const char* ppolicy_check_result_to_string(pwd_check_result_t result);
char* ppolicy_trim(char* str);
int ppolicy_strcasestr(const char* haystack, const char* needle);
int ppolicy_parse_string_list(const char* input, char** output, int max_count);
void ppolicy_free_string_list(char** list, int count);

/* 错误格式化 */
void ppolicy_format_error(
    pwd_check_result_t    result,
    char*                 buf,
    size_t                buf_size,
    ...
);

/* 各检查函数声明 */
pwd_check_result_t ppolicy_check_max_length(
    const char*     password,
    int             length,
    int             max_length
);

pwd_check_result_t ppolicy_check_charset(
    const char*     password,
    int             char_set
);

pwd_check_result_t ppolicy_check_no_user(
    pwd_user_context_t* user,
    const char*         password
);

pwd_check_result_t ppolicy_check_forbidden(
    const char*     password,
    const char*     forbidden_list
);

#endif /* PPOLICY_EXT_H */
