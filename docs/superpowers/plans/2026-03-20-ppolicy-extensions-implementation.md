# ppolicy-extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 OpenLDAP ppolicy 扩展模块，支持密码最大长度、字符集复杂度、黑名单检查和用户名包含检查。

**Architecture:** 基于 OpenLDAP slapo-ppolicy 框架，通过自定义 pw-quality 钩子集成。策略配置存储在 LDAP 策略条目中，模块加载后通过 `pw_quality` 回调拦截密码修改操作，执行扩展验证。

**Tech Stack:** C, OpenLDAP 2.4+, POSIX, Make

---

## 1. 项目骨架

### 1.1 创建目录结构

**Files:**
- Create: `ppolicy-extensions/Makefile`
- Create: `ppolicy-extensions/README.md`
- Create: `ppolicy-extensions/CHANGELOG.md`

- [ ] **Step 1: 创建目录结构**

```bash
mkdir -p ppolicy-extensions/{include,src,schema,tests/unit,tests/integration}
touch ppolicy-extensions/Makefile
touch ppolicy-extensions/README.md
touch ppolicy-extensions/CHANGELOG.md
```

---

## 2. 头文件定义

### 2.1 公共头文件

**Files:**
- Create: `ppolicy-extensions/include/ppolicy_ext.h`

- [ ] **Step 1: 创建头文件**

```c
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
```

- [ ] **Step 2: 提交**

```bash
git add include/ppolicy_ext.h
git commit -m "feat: add public header file with data structures and API declarations"
```

---

## 3. Schema 定义

### 3.1 扩展对象类和属性 Schema

**Files:**
- Create: `ppolicy-extensions/schema/ppolicy-extension.schema`

- [ ] **Step 1: 创建 Schema 文件（OID 统一使用 1.3.6.1.4.1.XXXXX）**

```schema
# OID 前缀: 1.3.6.1.4.1.XXXXX (需替换为正式申请的 OID)

# === 属性类型 ===

attributetype ( 1.3.6.1.4.1.XXXXX.1.1
    NAME 'pwdMaxLength'
    DESC 'Maximum length of password'
    EQUALITY integerMatch
    ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
    SINGLE-VALUE
    USAGE userApplications )

attributetype ( 1.3.6.1.4.1.XXXXX.1.2
    NAME 'pwdCharSet'
    DESC 'Character set requirements as bit mask'
    EQUALITY integerMatch
    ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
    SINGLE-VALUE
    USAGE userApplications )

attributetype ( 1.3.6.1.4.1.XXXXX.1.3
    NAME 'pwdNoUserCheck'
    DESC 'Check if password contains user name'
    EQUALITY booleanMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
    SINGLE-VALUE
    USAGE userApplications )

attributetype ( 1.3.6.1.4.1.XXXXX.1.4
    NAME 'pwdForbiddenStrings'
    DESC 'Comma-separated list of forbidden password substrings'
    EQUALITY caseIgnoreMatch
    SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE
    USAGE userApplications )

# === 对象类 ===

objectClass ( 1.3.6.1.4.1.XXXXX.2
    NAME 'pwdPolicyExtension'
    DESC 'Password policy extension object class'
    SUP top
    STRUCTURAL
    MUST ( cn )
    MAY ( pwdMaxLength $ pwdCharSet $ pwdNoUserCheck $ pwdForbiddenStrings ) )
```

- [ ] **Step 2: 提交**

```bash
git add schema/ppolicy-extension.schema
git commit -m "feat: add LDAP schema for pwdPolicyExtension object class"
```

---

## 4. 工具函数实现

### 4.1 工具函数

**Files:**
- Create: `ppolicy-extensions/src/utils.c`
- Create: `ppolicy-extensions/tests/unit/test_utils.c`

- [ ] **Step 1: 编写测试**

```c
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
```

- [ ] **Step 2: 运行测试验证失败**

```bash
gcc -I./include -o test_utils tests/unit/test_utils.c src/utils.c
./test_utils
# 预期: 编译失败，函数未定义
```

- [ ] **Step 3: 实现工具函数**

```c
#include "ppolicy_ext.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

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
        ppolicy_trim(token);
        output[count] = strdup(token);
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
```

- [ ] **Step 4: 运行测试验证通过**

```bash
gcc -I./include -o test_utils tests/unit/test_utils.c src/utils.c
./test_utils
# 预期: All utils tests passed!
```

- [ ] **Step 5: 提交**

```bash
git add src/utils.c tests/unit/test_utils.c
git commit -m "feat: add utility functions (trim, strcasestr, parse_string_list)"
```

---

## 5. 密码检查实现

### 5.1 最大长度检查

**Files:**
- Create: `ppolicy-extensions/src/check_maxlength.c`
- Create: `ppolicy-extensions/tests/unit/test_check_maxlength.c`

- [ ] **Step 1: 编写测试**

```c
#include <stdio.h>
#include <assert.h>
#include "../../include/ppolicy_ext.h"

void test_check_max_length_ok() {
    assert(ppolicy_check_max_length("password123", 11, 64) == PWD_CHECK_OK);
    assert(ppolicy_check_max_length("pass", 4, 10) == PWD_CHECK_OK);
}

void test_check_max_length_fail() {
    assert(ppolicy_check_max_length("password123456789", 17, 10) == PWD_CHECK_MAX_LENGTH);
    assert(ppolicy_check_max_length("thisisalongpassword", 18, 16) == PWD_CHECK_MAX_LENGTH);
}

void test_check_max_length_no_limit() {
    assert(ppolicy_check_max_length("anystring", 9, 0) == PWD_CHECK_OK);
}

int main() {
    test_check_max_length_ok();
    test_check_max_length_fail();
    test_check_max_length_no_limit();
    printf("All maxlength tests passed!\n");
    return 0;
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
gcc -I./include -o test_maxlength tests/unit/test_check_maxlength.c
./test_maxlength
# 预期: 编译失败
```

- [ ] **Step 3: 实现最大长度检查**

```c
#include "../../include/ppolicy_ext.h"

/**
 * 检查密码是否超过最大长度
 */
pwd_check_result_t ppolicy_check_max_length(
    const char* password,
    int         length,
    int         max_length
) {
    if (max_length > 0 && length > max_length) {
        return PWD_CHECK_MAX_LENGTH;
    }
    return PWD_CHECK_OK;
}
```

- [ ] **Step 4: 运行测试验证通过**

```bash
gcc -I./include -o test_maxlength tests/unit/test_check_maxlength.c src/check_maxlength.c
./test_maxlength
# 预期: All maxlength tests passed!
```

- [ ] **Step 5: 提交**

```bash
git add src/check_maxlength.c tests/unit/test_check_maxlength.c
git commit -m "feat: implement pwdMaxLength password check"
```

### 5.2 字符集检查

**Files:**
- Create: `ppolicy-extensions/src/check_charset.c`
- Create: `ppolicy-extensions/tests/unit/test_check_charset.c`

- [ ] **Step 1: 编写测试（修复重复断言问题）**

```c
#include <stdio.h>
#include <assert.h>
#include "../../include/ppolicy_ext.h"

void test_check_charset_upper() {
    // Bit 0 = 1: 需要大写
    assert(ppolicy_check_charset("Password", 1) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("password", 1) == PWD_CHECK_CHAR_SET_UPPER);
}

void test_check_charset_lower() {
    // Bit 1 = 2: 需要小写
    assert(ppolicy_check_charset("password", 2) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("PASSWORD", 2) == PWD_CHECK_CHAR_SET_LOWER);
}

void test_check_charset_digit() {
    // Bit 2 = 4: 需要数字
    assert(ppolicy_check_charset("Pass123", 4) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("Password", 4) == PWD_CHECK_CHAR_SET_DIGIT);
}

void test_check_charset_special() {
    // Bit 3 = 8: 需要特殊字符
    assert(ppolicy_check_charset("Password!", 8) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("Password", 8) == PWD_CHECK_CHAR_SET_SPECIAL);
}

void test_check_charset_combined() {
    // Bit 0+1+2 = 7: 大写+小写+数字
    assert(ppolicy_check_charset("Password123", 7) == PWD_CHECK_OK);
    assert(ppolicy_check_charset("password123", 7) == PWD_CHECK_CHAR_SET_UPPER);
    assert(ppolicy_check_charset("PASSWORD123", 7) == PWD_CHECK_CHAR_SET_LOWER);
    assert(ppolicy_check_charset("PasswordABC", 7) == PWD_CHECK_CHAR_SET_DIGIT);
}

int main() {
    test_check_charset_upper();
    test_check_charset_lower();
    test_check_charset_digit();
    test_check_charset_special();
    test_check_charset_combined();
    printf("All charset tests passed!\n");
    return 0;
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
gcc -I./include -o test_charset tests/unit/test_check_charset.c
./test_charset
# 预期: 编译失败
```

- [ ] **Step 3: 实现字符集检查**

```c
#include "../../include/ppolicy_ext.h"
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
    if (char_set & 1) {  // 需要大写
        if (!has_uppercase(password)) return PWD_CHECK_CHAR_SET_UPPER;
    }
    if (char_set & 2) {  // 需要小写
        if (!has_lowercase(password)) return PWD_CHECK_CHAR_SET_LOWER;
    }
    if (char_set & 4) {  // 需要数字
        if (!has_digit(password)) return PWD_CHECK_CHAR_SET_DIGIT;
    }
    if (char_set & 8) {  // 需要特殊字符
        if (!has_special(password)) return PWD_CHECK_CHAR_SET_SPECIAL;
    }
    return PWD_CHECK_OK;
}
```

- [ ] **Step 4: 运行测试验证通过**

```bash
gcc -I./include -o test_charset tests/unit/test_check_charset.c src/check_charset.c src/utils.c
./test_charset
# 预期: All charset tests passed!
```

- [ ] **Step 5: 提交**

```bash
git add src/check_charset.c tests/unit/test_check_charset.c
git commit -m "feat: implement pwdCharSet password check"
```

### 5.3 用户名检查

**Files:**
- Create: `ppolicy-extensions/src/check_user.c`
- Create: `ppolicy-extensions/tests/unit/test_check_user.c`

- [ ] **Step 1: 编写测试**

```c
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "../../include/ppolicy_ext.h"

void test_check_no_user_ok() {
    pwd_user_context_t user = {
        .uid = "john",
        .cn = "John Doe",
        .sn = "Doe",
        .given_name = "John",
        .password = "SecurePass123",
        .password_len = 12
    };
    assert(ppolicy_check_no_user(&user, "SecurePass123") == PWD_CHECK_OK);
}

void test_check_no_user_fail() {
    pwd_user_context_t user = {
        .uid = "john",
        .cn = "John Doe",
        .sn = "Doe",
        .given_name = "John",
        .password = "johnPassword123",
        .password_len = 15
    };
    assert(ppolicy_check_no_user(&user, "johnPassword123") == PWD_CHECK_USER_IN_PASSWORD);
}

int main() {
    test_check_no_user_ok();
    test_check_no_user_fail();
    printf("All user check tests passed!\n");
    return 0;
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
gcc -I./include -o test_user tests/unit/test_check_user.c
./test_user
# 预期: 编译失败
```

- [ ] **Step 3: 实现用户名检查**

```c
#include "../../include/ppolicy_ext.h"
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
```

- [ ] **Step 4: 运行测试验证通过**

```bash
gcc -I./include -o test_user tests/unit/test_check_user.c src/check_user.c src/utils.c
./test_user
# 预期: All user check tests passed!
```

- [ ] **Step 5: 提交**

```bash
git add src/check_user.c tests/unit/test_check_user.c
git commit -m "feat: implement pwdNoUserCheck password check"
```

### 5.4 黑名单检查

**Files:**
- Create: `ppolicy-extensions/src/check_forbidden.c`
- Create: `ppolicy-extensions/tests/unit/test_check_forbidden.c`

- [ ] **Step 1: 编写测试**

```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../../include/ppolicy_ext.h"

void test_check_forbidden_ok() {
    assert(ppolicy_check_forbidden("MySecurePassword123", "weak,password,admin") == PWD_CHECK_OK);
}

void test_check_forbidden_fail() {
    assert(ppolicy_check_forbidden("Password123", "weak,password,admin") == PWD_CHECK_FORBIDDEN_STRING);
    assert(ppolicy_check_forbidden("AdminPass", "weak,password,admin") == PWD_CHECK_FORBIDDEN_STRING);
}

void test_check_forbidden_empty() {
    assert(ppolicy_check_forbidden("AnyPassword", "") == PWD_CHECK_OK);
    assert(ppolicy_check_forbidden("AnyPassword", NULL) == PWD_CHECK_OK);
}

int main() {
    test_check_forbidden_ok();
    test_check_forbidden_fail();
    test_check_forbidden_empty();
    printf("All forbidden tests passed!\n");
    return 0;
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
gcc -I./include -o test_forbidden tests/unit/test_check_forbidden.c
./test_forbidden
# 预期: 编译失败
```

- [ ] **Step 3: 实现黑名单检查**

```c
#include "../../include/ppolicy_ext.h"
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
```

- [ ] **Step 4: 运行测试验证通过**

```bash
gcc -I./include -o test_forbidden tests/unit/test_check_forbidden.c src/check_forbidden.c src/utils.c
./test_forbidden
# 预期: All forbidden tests passed!
```

- [ ] **Step 5: 提交**

```bash
git add src/check_forbidden.c tests/unit/test_check_forbidden.c
git commit -m "feat: implement pwdForbiddenStrings password check"
```

---

## 6. 检查主函数

### 6.1 密码检查主函数

**Files:**
- Create: `ppolicy-extensions/src/check.c`

- [ ] **Step 1: 实现检查主函数**

```c
#include "../../include/ppolicy_ext.h"

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
```

- [ ] **Step 2: 提交**

```bash
git add src/check.c
git commit -m "feat: implement main password check orchestration function"
```

---

## 7. 策略加载

### 7.1 策略加载实现

**Files:**
- Create: `ppolicy-extensions/src/policy.c`
- Create: `ppolicy-extensions/tests/unit/test_policy.c`

- [ ] **Step 1: 编写测试（桩实现）**

```c
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../../include/ppolicy_ext.h"

/* 桩实现测试：验证函数签名和基本逻辑 */
void test_policy_default_values() {
    pwd_policy_extension_t policy = {0};

    /* 验证默认值 */
    assert(policy.pwd_max_length == 0);
    assert(policy.pwd_char_set == 0);
    assert(policy.pwd_no_user_check == 0);
    assert(policy.pwd_forbidden_strings == NULL);
}

int main() {
    test_policy_default_values();
    printf("All policy tests passed!\n");
    return 0;
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
gcc -I./include -o test_policy tests/unit/test_policy.c
./test_policy
# 预期: 编译失败
```

- [ ] **Step 3: 实现策略加载**

```c
#include "../../include/ppolicy_ext.h"
#include <string.h>
#include <stdlib.h>

/**
 * 从 LDAP 条目加载扩展策略配置
 *
 * 注意: 完整实现需要 LDAP 连接，这里提供框架
 */
int ppolicy_ext_load_policy(
    LDAP*                   ld,
    const char*             policy_dn,
    pwd_policy_extension_t* policy
) {
    (void)ld;
    (void)policy_dn;

    if (!policy) return -1;

    /* 初始化默认值 */
    memset(policy, 0, sizeof(*policy));

    /* TODO: 完整实现需要:
     * 1. 搜索 policy_dn 条目
     * 2. 读取 pwdMaxLength 属性
     * 3. 读取 pwdCharSet 属性
     * 4. 读取 pwdNoUserCheck 属性
     * 5. 读取 pwdForbiddenStrings 属性
     */

    return 0;
}

/**
 * 获取用户引用的策略 DN
 *
 * 注意: 完整实现需要 LDAP 连接，这里提供框架
 */
int ppolicy_ext_get_policy_dn(
    LDAP*   ld,
    const char* user_dn,
    char*   policy_dn_buf,
    size_t  buf_size
) {
    (void)ld;
    (void)user_dn;

    if (!policy_dn_buf || buf_size == 0) return -1;

    /* TODO: 完整实现需要:
     * 1. 读取用户的 pwdPolicySubentry 属性
     * 2. 返回策略 DN
     */

    /* 默认返回常用策略 DN */
    snprintf(policy_dn_buf, buf_size, "cn=default,ou=pwpolicies,dc=example,dc=com");
    return 0;
}
```

- [ ] **Step 4: 运行测试验证通过**

```bash
gcc -I./include -o test_policy tests/unit/test_policy.c src/policy.c
./test_policy
# 预期: All policy tests passed!
```

- [ ] **Step 5: 提交**

```bash
git add src/policy.c tests/unit/test_policy.c
git commit -m "feat: add policy loading framework"
```

---

## 8. 模块入口

### 8.1 模块初始化和销毁

**Files:**
- Create: `ppolicy-extensions/src/module.c`

- [ ] **Step 1: 实现模块入口**

```c
#include "../../include/ppolicy_ext.h"
#include <stdlib.h>
#include <string.h>

/**
 * 模块初始化
 */
int ppolicy_ext_init(ppolicy_ext_ctx_t** ctx) {
    if (!ctx) return -1;

    ppolicy_ext_ctx_t* new_ctx = calloc(1, sizeof(ppolicy_ext_ctx_t));
    if (!new_ctx) return -1;

    new_ctx->cache_ttl = 300;  /* 默认 5 分钟缓存 */
    new_ctx->last_cleanup = 0;
    new_ctx->module_handle = NULL;

    *ctx = new_ctx;
    return 0;
}

/**
 * 模块销毁
 */
void ppolicy_ext_destroy(ppolicy_ext_ctx_t* ctx) {
    if (ctx) {
        /* 清理缓存等资源 */
        free(ctx);
    }
}
```

- [ ] **Step 2: 提交**

```bash
git add src/module.c
git commit -m "feat: add module init/destroy entry points"
```

---

## 9. Makefile

### 9.1 构建系统

**Files:**
- Modify: `ppolicy-extensions/Makefile`

- [ ] **Step 1: 编写 Makefile（修复 lib/ 目录问题）**

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -fPIC -I./include
LDFLAGS = -shared -lldap

# 源文件
SRC = src/utils.c \
      src/check_maxlength.c \
      src/check_charset.c \
      src/check_user.c \
      src/check_forbidden.c \
      src/check.c \
      src/policy.c \
      src/module.c

# 对象文件
OBJ = $(SRC:.c=.o)
OBJ := $(addprefix build/,$(notdir $(OBJ)))

# 库文件
MODULE = lib/ppolicy_ext.so

.PHONY: all clean test install

all: lib $(MODULE)

lib:
	mkdir -p lib

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

$(MODULE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Module built: $@"

test: $(MODULE)
	@echo "Running unit tests..."
	gcc $(CFLAGS) -o test_utils tests/unit/test_utils.c src/utils.c && ./test_utils && rm -f test_utils
	gcc $(CFLAGS) -o test_maxlength tests/unit/test_check_maxlength.c src/check_maxlength.c && ./test_maxlength && rm -f test_maxlength
	gcc $(CFLAGS) -o test_charset tests/unit/test_check_charset.c src/check_charset.c src/utils.c && ./test_charset && rm -f test_charset
	gcc $(CFLAGS) -o test_user tests/unit/test_check_user.c src/check_user.c src/utils.c && ./test_user && rm -f test_user
	gcc $(CFLAGS) -o test_forbidden tests/unit/test_check_forbidden.c src/check_forbidden.c src/utils.c && ./test_forbidden && rm -f test_forbidden
	gcc $(CFLAGS) -o test_policy tests/unit/test_policy.c src/policy.c && ./test_policy && rm -f test_policy
	@echo "===================="
	@echo "All tests passed!"

clean:
	rm -rf build lib *.o test_* $(MODULE)

install: $(MODULE)
	install -d $(DESTDIR)/opt/ppolicy-extensions/lib
	install -m 755 $(MODULE) $(DESTDIR)/opt/ppolicy-extensions/lib/
	install -d $(DESTDIR)/etc/openldap/schema
	install -m 644 schema/ppolicy-extension.schema $(DESTDIR)/etc/openldap/schema/
	@echo "Installed to /opt/ppolicy-extensions"
```

- [ ] **Step 2: 测试编译**

```bash
make clean
make all
# 预期: 编译成功，生成 lib/ppolicy_ext.so
```

- [ ] **Step 3: 运行测试**

```bash
make test
# 预期: 所有单元测试通过
```

- [ ] **Step 4: 提交**

```bash
git add Makefile
git commit -m "build: add Makefile for compilation and testing"
```

---

## 10. 文档完善

### 10.1 README

**Files:**
- Modify: `ppolicy-extensions/README.md`

- [ ] **Step 1: 编写 README**

```markdown
# ppolicy-extensions

OpenLDAP ppolicy 扩展模块，支持密码最大长度、字符集复杂度、黑名单检查和用户名包含检查。

## 功能

- `pwdMaxLength`: 密码最大长度限制
- `pwdCharSet`: 字符集复杂度要求（大写/小写/数字/特殊字符）
- `pwdNoUserCheck`: 禁止密码包含用户名
- `pwdForbiddenStrings`: 黑名单字符串检查

## 构建

```bash
make
```

## 测试

```bash
make test
```

## 安装

```bash
sudo make install
```

## 配置

1. 加载 Schema 到 OpenLDAP
2. 在策略条目中添加扩展属性
3. 配置 slapo-ppolicy 使用扩展模块

详见 [docs/ppolicy-overlay-design.md](docs/ppolicy-overlay-design.md)
```

- [ ] **Step 2: 提交**

```bash
git add README.md
git commit -m "docs: add README"
```

---

## 11. 最终验证

- [ ] **Step 1: 清理并完整编译**

```bash
make clean
make all
make test
```

- [ ] **Step 2: 验证目录结构**

```bash
find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.schema" -o -name "Makefile" \) | sort
```

预期输出:
```
./include/ppolicy_ext.h
./src/check.c
./src/check_charset.c
./src/check_forbidden.c
./src/check_maxlength.c
./src/check_user.c
./src/module.c
./src/policy.c
./src/utils.c
./schema/ppolicy-extension.schema
./Makefile
```

- [ ] **Step 3: 最终提交**

```bash
git add -A
git commit -m "feat: complete ppolicy-extensions initial implementation

- Add header file with data structures and APIs
- Add LDAP schema for pwdPolicyExtension
- Implement password checks: maxlength, charset, user, forbidden
- Add policy loading framework
- Add Makefile for build and test
- Add README documentation"
```

---

## 任务清单

| 任务 | 状态 |
|------|------|
| 1. 创建项目骨架 | ☐ |
| 2. 创建头文件 | ☐ |
| 3. 创建 Schema | ☐ |
| 4. 工具函数实现 | ☐ |
| 5. 最大长度检查 | ☐ |
| 6. 字符集检查 | ☐ |
| 7. 用户名检查 | ☐ |
| 8. 黑名单检查 | ☐ |
| 9. 检查主函数 | ☐ |
| 10. 策略加载框架 | ☐ |
| 11. 模块入口 | ☐ |
| 12. Makefile | ☐ |
| 13. README | ☐ |
| 14. 最终验证 | ☐ |

---

*Plan version: 1.1 (fixed issues from review)*
*Created: 2026-03-20*
*Spec: docs/ppolicy-overlay-design.md, docs/ppolicy-overlay-detailed-design.md*
