# OpenLDAP ppolicy 扩展模块详细设计文档

## 1. 概述

本文档是 `ppolicy-overlay-design.md` 的详细补充，描述 OpenLDAP ppolicy 扩展模块的实现细节，包括数据结构、API 接口、调用流程、错误处理和构建步骤。

---

## 2. 数据结构定义

### 2.1 策略配置结构体

```c
// 文件: include/ppolicy_ext.h

#ifndef PPOLICY_EXT_H
#define PPOLICY_EXT_H

#include <ldap.h>
#include <sys/types.h>

/**
 * 扩展密码策略配置
 */
typedef struct pwd_policy_extension {
    // === 扩展属性 ===
    int         pwd_max_length;        // 密码最大长度，0表示不限制
    int         pwd_char_set;          // 字符集选项位标志
    int         pwd_no_user_check;     // 是否检查用户名包含
    char*       pwd_forbidden_strings;  // 黑名单字符串（逗号分隔）

    // === 缓存标识 ===
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
 * 检查结果
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

/**
 * 模块上下文
 */
typedef struct ppolicy_ext_ctx {
    void*               module_handle;      // 模块句柄
    pwd_policy_extension_t* policy_cache;   // 策略缓存
    LDAP*               ld;                  // LDAP 连接
} ppolicy_ext_ctx_t;

#endif /* PPOLICY_EXT_H */
```

### 2.2 策略缓存结构

```c
// 文件: src/policy_cache.h

#include "ppolicy_ext.h"

/**
 * 链表节点 - 存储每个 DN 的策略配置
 */
typedef struct policy_cache_entry {
    char*                   dn;                     // 策略 DN
    pwd_policy_extension_t   ext;                    // 扩展配置
    time_t                   cache_time;              // 缓存时间
    struct policy_cache_entry* next;                  // 下一个节点
} policy_cache_entry_t;

/**
 * 全局策略缓存管理器
 */
typedef struct policy_cache_manager {
    policy_cache_entry_t*    head;                   // 链表头
    int                     count;                   // 缓存条目数
    time_t                  last_cleanup;            // 最后清理时间
} policy_cache_manager_t;
```

---

## 3. API 接口定义

### 3.1 模块初始化/销毁

```c
// 文件: src/module.c

/**
 * 模块初始化
 *
 * @param ctx 模块上下文
 * @return 0 成功，非0 失败
 */
int ppolicy_ext_init(ppolicy_ext_ctx_t* ctx);

/**
 * 模块销毁
 *
 * @param ctx 模块上下文
 */
void ppolicy_ext_destroy(ppolicy_ext_ctx_t* ctx);
```

### 3.2 策略加载

```c
// 文件: src/policy.c

/**
 * 从 LDAP 条目加载扩展策略配置
 *
 * @param ld LDAP 连接
 * @param policy_dn 策略条目 DN
 * @param ext 输出的扩展配置
 * @return 0 成功，非0 失败
 */
int ppolicy_ext_load_policy(
    LDAP*           ld,
    const char*     policy_dn,
    pwd_policy_extension_t* ext
);

/**
 * 获取用户引用的策略 DN
 *
 * @param ld LDAP 连接
 * @param user_dn 用户 DN
 * @param policy_dn_buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 0 成功，非0 失败
 */
int ppolicy_ext_get_policy_dn(
    LDAP*           ld,
    const char*     user_dn,
    char*           policy_dn_buf,
    size_t          buf_size
);
```

### 3.3 密码检查

```c
// 文件: src/check.c

/**
 * 执行所有扩展检查
 *
 * @param ctx 模块上下文
 * @param user 用户上下文
 * @param policy 策略配置
 * @return LDAP 错误码 (LDAP_SUCCESS = 成功)
 */
int ppolicy_ext_check_password(
    ppolicy_ext_ctx_t*      ctx,
    pwd_user_context_t*    user,
    pwd_policy_extension_t* policy
);

/**
 * 检查密码最大长度
 *
 * @param password 密码
 * @param length 密码长度
 * @param max_length 最大长度限制
 * @return PWD_CHECK_OK 或错误码
 */
pwd_check_result_t ppolicy_check_max_length(
    const char*     password,
    int             length,
    int             max_length
);

/**
 * 检查字符集要求
 *
 * @param password 密码
 * @param char_set 位标志
 * @return PWD_CHECK_OK 或第一个失败的检查码
 */
pwd_check_result_t ppolicy_check_charset(
    const char*     password,
    int             char_set
);

/**
 * 检查密码是否包含用户名
 *
 * @param user 用户上下文
 * @param password 密码
 * @return PWD_CHECK_OK 或 PWD_CHECK_USER_IN_PASSWORD
 */
pwd_check_result_t ppolicy_check_no_user(
    pwd_user_context_t* user,
    const char*         password
);

/**
 * 检查黑名单
 *
 * @param password 密码
 * @param forbidden_list 逗号分隔的黑名单
 * @return PWD_CHECK_OK 或 PWD_CHECK_FORBIDDEN_STRING
 */
pwd_check_result_t ppolicy_check_forbidden(
    const char*     password,
    const char*     forbidden_list
);
```

### 3.4 工具函数

```c
// 文件: src/utils.c

/**
 * 转换为错误消息
 *
 * @param result 检查结果
 * @return 错误消息字符串
 */
const char* ppolicy_check_result_to_string(pwd_check_result_t result);

/**
 * 解析逗号分隔的字符串列表
 *
 * @param input 输入字符串
 * @param output 输出数组
 * @param max_count 最大条目数
 * @return 实际解析的条目数
 */
int ppolicy_parse_string_list(
    const char*     input,
    char**          output,
    int             max_count
);

/**
 * 去除字符串两端空白
 *
 * @param str 输入字符串（就地修改）
 * @return 修政后的字符串
 */
char* ppolicy_trim(char* str);

/**
 * 大小写不敏感的子串查找
 *
 * @param haystack 主字符串
 * @param needle 子字符串
 * @return 找到返回非0，未找到返回0
 */
int ppolicy_strcasestr(const char* haystack, const char* needle);
```

---

## 4. 调用时序图

### 4.1 密码修改完整流程

```
┌─────────┐     ┌──────────────┐     ┌────────────────┐     ┌────────────────────┐
│  客户端  │     │  OpenLDAP    │     │ slapo-ppolicy  │     │ 自定义 pw-quality  │
└────┬────┘     └──────┬───────┘     └───────┬────────┘     └─────────┬──────────┘
     │                  │                      │                       │
     │ LDAP modify      │                      │                       │
     │ (修改密码)        │                      │                       │
     │─────────────────>│                      │                       │
     │                  │                      │                       │
     │                  │ PasswordModify        │                       │
     │                  │ Request               │                       │
     │                  │──────────────────────>│                       │
     │                  │                      │                       │
     │                  │                      │ 检查 pwdMinLength      │
     │                  │                      │ 检查 pwdInHistory      │
     │                  │                      │ 检查 pwdMinAge         │
     │                  │                      │ ...                    │
     │                  │                      │                        │
     │                  │                      │                        │
     │                  │                      │ 调用扩展检查            │
     │                  │                      │───────────────────────>│
     │                  │                      │                        │
     │                  │                      │                 ┌───────▼───────┐
     │                  │                      │                 │ 获取策略DN    │
     │                  │                      │                 │ 加载策略配置   │
     │                  │                      │                 │ (pwdMaxLength │
     │                  │                      │                 │  pwdCharSet   │
     │                  │                      │                 │  pwdNoUser    │
     │                  │                      │                 │  pwdForbidden)│
     │                  │                      │                 └───────┬───────┘
     │                  │                      │                        │
     │                  │                      │                        │ 依次执行检查:
     │                  │                      │                        │ 1. max_length
     │                  │                      │                        │ 2. charset
     │                  │                      │                        │ 3. no_user
     │                  │                      │                        │ 4. forbidden
     │                  │                      │                        │
     │                  │                      │    <─ 返回结果 ─────────│
     │                  │                      │                        │
     │                  │                      │                       │
     │<─────────────────│                      │                       │
     │  LDAP Result      │                      │                       │
     │  (成功/错误)       │                      │                       │
     │                  │                      │                       │
```

### 4.2 扩展检查内部流程

```
┌─────────────────────────────────────────────────────────────────┐
│                  ppolicy_ext_check_password                      │
└────────────────────────────────┬────────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ 检查 pwdMaxLength│    │  检查 pwdCharSet │    │检查pwdNoUserCheck│
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                     │                     │
         │                     │                     │
         ▼                     ▼                     ▼
    ┌────────┐            ┌────────┐            ┌────────┐
    │ length │            │ has_   │            │ 检查   │
    │ > max ?│            │ upper? │            │ uid in │
    └────┬───┘            └────┬───┘            │ pwd ?  │
         │                     │                     │
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│返回MAX_LENGTH错误│    │返回第一个失败的 │    │返回USER错误    │
│或继续检查        │    │charset错误或继续│    │或继续检查       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               │
                               ▼
                    ┌─────────────────┐
                    │检查pwdForbidden │
                    │Strings          │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ 找到禁用字符串? │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │返回FORBIDDEN错误 │           │ 返回 PWD_CHECK_OK│
    └─────────────────┘           └─────────────────┘
```

---

## 5. 错误码详细定义

### 5.1 LDAP 错误码映射

| 检查结果 | LDAP 错误码 | 错误消息 | HTTP 对应 |
|----------|------------|----------|----------|
| `PWD_CHECK_OK` | `LDAP_SUCCESS` | 成功 | 200 |
| `PWD_CHECK_MAX_LENGTH` | `LDAP_CONSTRAINT_VIOLATION` | Password too long | 400 |
| `PWD_CHECK_CHAR_SET_UPPER` | `LDAP_CONSTRAINT_VIOLATION` | Password must contain uppercase letter | 400 |
| `PWD_CHECK_CHAR_SET_LOWER` | `LDAP_CONSTRAINT_VIOLATION` | Password must contain lowercase letter | 400 |
| `PWD_CHECK_CHAR_SET_DIGIT` | `LDAP_CONSTRAINT_VIOLATION` | Password must contain digit | 400 |
| `PWD_CHECK_CHAR_SET_SPECIAL` | `LDAP_CONSTRAINT_VIOLATION` | Password must contain special character | 400 |
| `PWD_CHECK_USER_IN_PASSWORD` | `LDAP_CONSTRAINT_VIOLATION` | Password contains user name | 400 |
| `PWD_CHECK_FORBIDDEN_STRING` | `LDAP_CONSTRAINT_VIOLATION` | Password contains forbidden string | 400 |

### 5.2 扩展错误消息

```c
// 文件: src/errors.c

static const char* error_messages[] = {
    [PWD_CHECK_OK]                    = "Success",
    [PWD_CHECK_MAX_LENGTH]            = "Password exceeds maximum length of %d characters",
    [PWD_CHECK_CHAR_SET_UPPER]        = "Password must contain at least one uppercase letter (A-Z)",
    [PWD_CHECK_CHAR_SET_LOWER]        = "Password must contain at least one lowercase letter (a-z)",
    [PWD_CHECK_CHAR_SET_DIGIT]        = "Password must contain at least one digit (0-9)",
    [PWD_CHECK_CHAR_SET_SPECIAL]      = "Password must contain at least one special character",
    [PWD_CHECK_USER_IN_PASSWORD]      = "Password must not contain your user name",
    [PWD_CHECK_FORBIDDEN_STRING]      = "Password contains a forbidden string"
};

/**
 * 获取格式化错误消息
 *
 * @param result 检查结果
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @param ... 可选参数（如最大长度值）
 */
void ppolicy_format_error(
    pwd_check_result_t    result,
    char*                 buf,
    size_t                buf_size,
    ...
);
```

### 5.3 错误处理策略

1. **短路执行**: 各检查项按固定顺序执行，遇到第一个失败立即返回
2. **静默忽略**: 未配置的检查项直接跳过（如 `pwdMaxLength=0` 表示不检查）
3. **日志记录**: 所有失败操作记录到 OpenLDAP 日志（`slapd.log`）

---

## 6. 配置文件格式

### 6.1 slapd.conf 配置

```conf
# 文件: /etc/openldap/slapd.conf

# === 加载模块 ===
modulepath /usr/lib/openldap
moduleload back_mdb

# === 加载原生 ppolicy ===
moduleload ppolicy
overlay ppolicy

# === 加载自定义扩展模块 ===
modulepath /opt/ppolicy-extensions/lib
moduleload ppolicy_ext

# === 扩展模块配置 ===
ppolicy_ext_module {
    # 缓存过期时间（秒），0 表示不缓存
    cache_ttl 300

    # 默认最大长度（当策略未设置时）
    default_max_length 128

    # 默认字符集要求
    default_char_set 0

    # 是否默认启用用户名检查
    default_no_user_check FALSE

    # 默认黑名单文件路径
    # forbidden_dict /opt/ppolicy-extensions/dict.txt
}

# === 原生 ppolicy 配置 ===
ppolicy_default "cn=default,ou=pwpolicies,dc=example,dc=com"

# === 数据库配置 ===
database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory /var/lib/openldap/data
```

### 6.2 cn=config 配置 (OLC)

```ldif
# 加载模块
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/openldap
olcModuleLoad: ppolicy

# 添加扩展模块配置
dn: olcOverlay=ppolicy_ext,olcDatabase={1}mdb,cn=config
objectClass: olcPPolicyExtensionConfig
olcPPolicyExtCacheTTL: 300
olcPPolicyExtDefaultMaxLength: 128
olcPPolicyExtDefaultCharSet: 0
olcPPolicyExtDefaultNoUserCheck: FALSE
# olcPPolicyExtForbiddenDict: /opt/ppolicy-extensions/dict.txt
```

### 6.3 策略条目配置

```ldif
# 密码策略条目
dn: cn=default,ou=pwpolicies,dc=example,dc=com
objectClass: top
objectClass: pwdPolicy
objectClass: pwdPolicyExtension
cn: default
desc: Default password policy with extensions

# === 原生属性 ===
pwdMinLength: 8
pwdMaxAge: 7776000
pwdMinAge: 0
pwdExpireWarning: 1296000
pwdInHistory: 5
pwdMustChange: FALSE
pwdCheckQuality: 1

# === 扩展属性 ===
pwdMaxLength: 64
pwdCharSet: 7
pwdNoUserCheck: TRUE
pwdForbiddenStrings: weak,password123,admin,123456,letmein,iloveyou
```

---

## 7. 构建步骤

### 7.1 目录结构

```
ppolicy-extensions/
├── docs/
│   ├── ppolicy-overlay-design.md          # 概要设计
│   └── ppolicy-overlay-detailed-design.md  # 本文档
├── include/
│   └── ppolicy_ext.h                      # 公共头文件
├── src/
│   ├── module.c                           # 模块入口
│   ├── policy.c                           # 策略加载
│   ├── check.c                           # 密码检查主函数
│   ├── check_maxlength.c                  # 最大长度检查
│   ├── check_charset.c                    # 字符集检查
│   ├── check_user.c                       # 用户名检查
│   ├── check_forbidden.c                  # 黑名单检查
│   ├── errors.c                           # 错误处理
│   ├── utils.c                            # 工具函数
│   └── policy_cache.c                      # 策略缓存
├── schema/
│   └── ppolicy-extension.schema            # Schema 定义
├── tests/
│   ├── unit/
│   │   ├── test_check_maxlength.c
│   │   ├── test_check_charset.c
│   │   ├── test_check_user.c
│   │   └── test_check_forbidden.c
│   └── integration/
│       └── test_integration.c
├── Makefile
├── README.md
└── CHANGELOG.md
```

### 7.2 依赖安装

**Debian/Ubuntu:**
```bash
apt-get update
apt-get install -y \
    build-essential \
    libldap-dev \
    slapd \
    ldap-utils
```

**RHEL/CentOS:**
```bash
yum groupinstall -y "Development Tools"
yum install -y openldap-devel
```

### 7.3 编译

```bash
# 克隆项目
cd /home/ut000930@uos/works/ppolicy-extensions

# 查看目录结构
ls -la

# 编译
make

# 预期输出:
# cc -fPIC -I./include -c src/check_maxlength.c -o build/check_maxlength.o
# cc -fPIC -I./include -c src/check_charset.c -o build/check_charset.o
# ...
# cc -shared -o lib/ppolicy_ext.so build/*.o
# ld -rpath /usr/lib/openldap -o lib/ppolicy_ext.la
```

### 7.4 安装

```bash
# 安装模块
sudo make install

# 安装位置:
# - 模块: /opt/ppolicy-extensions/lib/ppolicy_ext.so
# - Schema: /etc/openldap/schema/ppolicy-extension.schema
```

### 7.5 测试

```bash
# 运行单元测试
make test

# 预期输出:
# Running test_check_maxlength... PASSED
# Running test_check_charset... PASSED
# Running test_check_user... PASSED
# Running test_check_forbidden... PASSED
# =====================
# 4 tests, 0 failures
```

---

## 8. Schema 定义

### 8.1 OID 分配

| OID | 对象/属性 | 说明 |
|-----|-----------|------|
| `1.3.6.1.4.1.XXXXX` | ppolicyExtension | 根 OID（需向 IANA 申请） |
| `1.3.6.1.4.1.XXXXX.1` | pwdPolicyExtension | 对象类 |
| `1.3.6.1.4.1.XXXXX.1.1` | pwdMaxLength | 属性 |
| `1.3.6.1.4.1.XXXXX.1.2` | pwdCharSet | 属性 |
| `1.3.6.1.4.1.XXXXX.1.3` | pwdNoUserCheck | 属性 |
| `1.3.6.1.4.1.XXXXX.1.4` | pwdForbiddenStrings | 属性 |

### 8.2 Schema 文件

```schema
# 文件: schema/ppolicy-extension.schema

# === OID 声明 ===
# OID 前缀: 1.3.6.1.4.1.XXXXX (需要替换为正式申请的 OID)

# === 属性类型 ===

# pwdMaxLength - 密码最大长度
attributetype ( 1.3.6.1.4.1.XXXXX.1.1
    NAME 'pwdMaxLength'
    DESC 'Maximum length of password'
    EQUALITY integerMatch
    ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
    SINGLE-VALUE
    USAGE userApplications )

# pwdCharSet - 字符集选项
attributetype ( 1.3.6.1.4.1.XXXXX.1.2
    NAME 'pwdCharSet'
    DESC 'Character set requirements as bit mask'
    EQUALITY integerMatch
    ORDERING integerOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
    SINGLE-VALUE
    USAGE userApplications )

# pwdNoUserCheck - 是否检查密码包含用户名
attributetype ( 1.3.6.1.4.1.XXXXX.1.3
    NAME 'pwdNoUserCheck'
    DESC 'Check if password contains user name'
    EQUALITY booleanMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
    SINGLE-VALUE
    USAGE userApplications )

# pwdForbiddenStrings - 禁用字符串列表
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

---

## 9. 接口集成点

### 9.1 slapo-ppolicy 集成

自定义模块通过 `pw_quality` 钩子与 slapo-ppolicy 集成：

```c
// 在 slapo-ppolicy 中配置 pw_quality
ppolicy_default "cn=default,ou=pwpolicies,dc=example,dc=com"
```

当密码修改时，slapo-ppolicy 调用 `pw_quality` 钩子，自定义模块在该钩子中执行扩展检查。

### 9.2 检查函数签名

```c
/**
 * pw_quality 钩子函数类型
 *
 * @param conn 连接上下文
 * @param op 操作上下文
 * @param pw 密码值
 * @param uuiddn 用户 DN
 * @param sc 策略配置
 * @return LDAP 错误码
 */
typedef int (*pw_quality_func_t)(
    Connection*     conn,
    Operation*      op,
    struct berval*  pw,
    struct DN*      uuiddn,
    Syntax*         sc
);

// 自定义模块导出
int ppolicy_ext_quality_check(
    Connection*     conn,
    Operation*      op,
    struct berval*  pw,
    struct DN*      uuiddn,
    Syntax*         sc
);
```

---

## 10. 缓存策略

### 10.1 缓存设计

```
┌─────────────────────────────────────────────────────────────┐
│                  策略缓存管理器                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐      │
│  │ DN: cn=...  │   │ DN: cn=...  │   │ DN: cn=...  │ ...  │
│  │ pwdMaxLength│   │ pwdMaxLength│   │ pwdMaxLength│      │
│  │ pwdCharSet  │   │ pwdCharSet  │   │ pwdCharSet  │      │
│  │ cache_time  │   │ cache_time  │   │ cache_time  │      │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘      │
│         │                 │                 │              │
│         └─────────────────┼─────────────────┘              │
│                           │                                │
│                      哈希表 / 链表                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 缓存失效

- **TTL 过期**: 默认 300 秒后自动失效
- **手动刷新**: 通过 LDAP 操作删除策略条目时触发
- **容量限制**: 最大缓存 1000 条，超出后清除最旧条目

---

## 11. 性能基准

### 11.1 预期性能

| 检查项 | 时间复杂度 | 典型耗时 |
|--------|-----------|----------|
| pwdMaxLength | O(1) | < 0.01ms |
| pwdCharSet | O(n) | < 0.1ms |
| pwdNoUserCheck | O(n*m) | < 0.5ms |
| pwdForbiddenStrings | O(n*k) | < 1ms |

注: n=密码长度, m=用户名属性数, k=黑名单词条数

### 11.2 优化建议

1. **黑名单优化**: 词条数 > 100 时，使用 Trie 树或 Aho-Corasick 自动机
2. **缓存预热**: 服务启动时预加载常用策略
3. **异步日志**: 错误日志写入异步队列，避免阻塞

---

*文档版本: 1.0*
*创建日期: 2026-03-20*
*关联文档: ppolicy-overlay-design.md*
