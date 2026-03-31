#include "ppolicy_ext.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/*
 * OpenLDAP slapo-ppolicy 内部类型前向声明。
 */
typedef struct Entry Entry;

/* 策略必须通过 pArg (pwdCheckModuleArg) 传递，不再支持配置文件回退 */

/*
 * 从 DN 字符串中提取 uid 值。
 * 例如: "uid=testuser,ou=people,dc=example,dc=com" -> "testuser"
 * 返回值需要调用者 free()。
 */
static char* extract_uid_from_dn(const char* dn) {
    if (!dn) return NULL;

    const char* uid_start = NULL;
    if (strncasecmp(dn, "uid=", 4) == 0) {
        uid_start = dn + 4;
    } else {
        const char* p = dn;
        while (*p) {
            if (*p == ',' && strncasecmp(p + 1, "uid=", 4) == 0) {
                uid_start = p + 5;
                break;
            }
            p++;
        }
    }

    if (!uid_start) return NULL;

    const char* uid_end = strchr(uid_start, ',');
    size_t len = uid_end ? (size_t)(uid_end - uid_start) : strlen(uid_start);

    char* uid = malloc(len + 1);
    if (uid) {
        memcpy(uid, uid_start, len);
        uid[len] = '\0';
    }
    return uid;
}

static char* trim_whitespace(char* str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    return str;
}

/*
 * 解析 key=value 格式的策略配置行到 policy 结构体。
 */
static void parse_policy_line(const char* key, const char* val, pwd_policy_extension_t* policy) {
    if (strcasecmp(key, "extPwdMaxLength") == 0) {
        policy->pwd_max_length = atoi(val);
    } else if (strcasecmp(key, "extPwdCharSet") == 0) {
        policy->pwd_char_set = atoi(val);
    } else if (strcasecmp(key, "extPwdNoUserCheck") == 0) {
        policy->pwd_no_user_check = (strcasecmp(val, "TRUE") == 0) ? 1 : 0;
    } else if (strcasecmp(key, "extPwdForbiddenStrings") == 0) {
        free(policy->pwd_forbidden_strings);
        policy->pwd_forbidden_strings = strdup(val);
    }
}

/*
 * 从 pwdCheckModuleArg (pArg) 字符串解析策略。
 *
 * ppolicy overlay 在调用 check_password 之前，已经通过内部 API
 * 读取了策略条目的 pwdCheckModuleArg 属性，并通过 pArg 传入。
 *
 * 支持的分隔符：换行符 '\n' 或空格 ' '
 * 格式（空格或换行分隔的 key=value 对）：
 *   extPwdMaxLength=64 extPwdCharSet=7 extPwdNoUserCheck=TRUE extPwdForbiddenStrings=weak,admin
 *
 * 客户端通过 ldapmodify 修改即时生效：
 *   ldapmodify -x -H ldap://... -D "cn=admin,..." -w ... <<EOF
 *   dn: cn=default,ou=pwpolicies,dc=example,dc=com
 *   changetype: modify
 *   replace: pwdCheckModuleArg
 *   pwdCheckModuleArg: extPwdMaxLength=32 extPwdCharSet=15 extPwdNoUserCheck=TRUE extPwdForbiddenStrings=weak,admin,password
 *   EOF
 */
static int load_policy_from_arg(const char* arg_str, size_t arg_len, pwd_policy_extension_t* policy) {
    if (!arg_str || arg_len == 0) return -1;

    memset(policy, 0, sizeof(*policy));

    /* 复制一份以便安全修改 */
    char* buf = malloc(arg_len + 1);
    if (!buf) return -1;
    memcpy(buf, arg_str, arg_len);
    buf[arg_len] = '\0';

    /* 逐 token 解析（支持换行符和空格分隔） */
    char* saveptr = NULL;
    char* token = strtok_r(buf, " \n", &saveptr);
    while (token) {
        char* trimmed = trim_whitespace(token);
        if (*trimmed == '#' || *trimmed == '\0') {
            token = strtok_r(NULL, " \n", &saveptr);
            continue;
        }

        char* eq = strchr(trimmed, '=');
        if (eq) {
            *eq = '\0';
            char* key = trim_whitespace(trimmed);
            char* val = trim_whitespace(eq + 1);
            parse_policy_line(key, val, policy);
        }

        token = strtok_r(NULL, " \n", &saveptr);
    }

    free(buf);
    return 0;
}


/*
 * check_password — slapo-ppolicy 标准入口点。
 *
 * 策略加载优先级：
 *   1. 从 pArg (pwdCheckModuleArg) 解析 — 支持 LDAP 客户端动态修改
 *   2. 回退到配置文件 /etc/ldap/ppolicy_ext.conf
 *
 * 客户端修改策略示例（即时生效，无需重启 slapd）：
 *   ldapmodify ... <<EOF
 *   dn: cn=default,ou=pwpolicies,dc=example,dc=com
 *   changetype: modify
 *   replace: pwdCheckModuleArg
 *   pwdCheckModuleArg: extPwdMaxLength=32
 *    extPwdCharSet=15
 *    extPwdNoUserCheck=TRUE
 *    extPwdForbiddenStrings=weak,admin,password
 *   EOF
 */
int check_password(char *pPasswd, struct berval *pErrmsg, Entry *pEntry, struct berval *pArg) {
    ppolicy_ext_ctx_t* ctx = NULL;
    pwd_policy_extension_t policy;
    pwd_user_context_t user;
    pwd_check_result_t result;
    char errbuf[256];

    memset(&policy, 0, sizeof(policy));
    memset(&user, 0, sizeof(user));

    if (!pPasswd) {
        snprintf(errbuf, sizeof(errbuf), "Password is empty");
        goto fail;
    }

    /* 初始化上下文 */
    if (ppolicy_ext_init(&ctx) != 0) {
        snprintf(errbuf, sizeof(errbuf), "Failed to initialize ppolicy extension");
        goto fail;
    }

    /* 从 pwdCheckModuleArg 加载策略（可选） */
    if (pArg && pArg->bv_val && pArg->bv_len > 0) {
        load_policy_from_arg(pArg->bv_val, pArg->bv_len, &policy);
    }
    /* 无策略时使用全0 policy，跳过所有检查（相当于无约束） */

    /* 构建用户上下文 */
    user.password = pPasswd;
    user.password_len = (int)strlen(pPasswd);

    /*
     * 从 Entry 中提取用户 DN。
     *
     * Entry 结构（servers/slapd/slap.h）:
     *   struct Entry {
     *       ID              e_id;       // unsigned long (8 bytes on 64-bit)
     *       struct berval   e_name;     // DN
     *       ...
     *   };
     */
    if (pEntry) {
        struct berval* e_name = (struct berval*)((char*)pEntry + sizeof(unsigned long));
        if (e_name->bv_val && e_name->bv_len > 0) {
            user.dn = e_name->bv_val;
            user.uid = extract_uid_from_dn(user.dn);
        }
    }

    /* 执行密码检查 */
    result = ppolicy_ext_check_password(ctx, &user, &policy);

    if (result != PWD_CHECK_OK) {
        ppolicy_format_error(result, errbuf, sizeof(errbuf));
        goto fail;
    }

    /* 清理 */
    free(user.uid);
    free(policy.pwd_forbidden_strings);
    ppolicy_ext_destroy(ctx);
    return LDAP_SUCCESS;

fail:
    if (pErrmsg) {
        pErrmsg->bv_val = strdup(errbuf);
        pErrmsg->bv_len = strlen(errbuf);
    }
    free(user.uid);
    free(policy.pwd_forbidden_strings);
    ppolicy_ext_destroy(ctx);
    return LDAP_CONSTRAINT_VIOLATION;
}
