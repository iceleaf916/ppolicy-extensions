# OpenLDAP ppolicy 扩展模块设计文档

## 1. 项目概述

### 1.1 项目名称
`ppolicy-extensions` - OpenLDAP 密码策略扩展模块

### 1.2 项目目标
基于 OpenLDAP 原生 `slapo-ppolicy` overlay，实现扩展的密码策略验证功能，提供可配置的密码最大长度、字符集复杂度、黑名单检查和用户名包含检查。

### 1.3 需求来源
参见 `list.md` 需求文档。

### 1.4 扩展项清单

| 序号 | 策略项 | 实现方式 |
|------|--------|----------|
| 1 | 密码最大长度 | 扩展属性 `pwdMaxLength` |
| 2 | 允许输入字符集 | 扩展属性 `pwdCharSet` |
| 3 | 必须同时包含多类字符 | 依赖 `pwdCharSet` |
| 4 | 禁止密码包含用户名 | 扩展属性 `pwdNoUserCheck` |
| 5 | 不允许包含特定字符串 | 扩展属性 `pwdForbiddenStrings` |

### 1.5 非扩展项（原生支持）

| 序号 | 策略项 | 对应属性 |
|------|--------|----------|
| 1 | 密码长度范围 - 最小长度 | `pwdMinLength` |
| 2 | 密码有效期（90天） | `pwdMaxAge` |
| 3 | 密码最短使用期限 | `pwdMinAge` |
| 4 | 即将到期提醒 | `pwdExpireWarning` |
| 5 | 历史密码检查 | `pwdInHistory` |
| 6 | 强制修改密码标记 | `pwdMustChange` |

---

## 2. 技术架构

### 2.1 模块层次

```
┌─────────────────────────────────────────────────────────────┐
│                       OpenLDAP                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              slapo-ppolicy (原生)                     │   │
│  │  ├── pwdMinLength (最小长度)                          │   │
│  │  ├── pwdMaxAge (有效期)                              │   │
│  │  ├── pwdMinAge (最短使用期)                          │   │
│  │  ├── pwdExpireWarning (到期提醒)                     │   │
│  │  ├── pwdInHistory (历史记录)                          │   │
│  │  └── pwdMustChange (强制修改)                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            ▼                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           自定义 pw-quality 模块 (扩展)                │   │
│  │  ├── pwdMaxLength (最大长度)                          │   │
│  │  ├── pwdCharSet (字符集选项)                          │   │
│  │  ├── pwdNoUserCheck (用户名检查)                       │   │
│  │  └── pwdForbiddenStrings (黑名单)                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 模块交互流程

```
用户修改密码
    │
    ▼
┌─────────────────────────────────────────┐
│     slapo-ppolicy (原生模块)              │
│  ├── 检查 pwdMinLength                   │
│  ├── 检查 pwdInHistory                   │
│  └── 其他原生检查...                      │
└─────────────────────────────────────────┘
    │
    ▼ (原生检查通过后)
┌─────────────────────────────────────────┐
│     自定义 pw-quality 模块               │
│  ├── 检查 pwdMaxLength                   │
│  ├── 检查 pwdCharSet                     │
│  ├── 检查 pwdNoUserCheck                 │
│  └── 检查 pwdForbiddenStrings            │
└─────────────────────────────────────────┘
    │
    ▼
密码修改成功 / 返回错误
```

### 2.3 技术选型

- **实现语言**: C
- **依赖**: OpenLDAP 2.4+，OpenLDAP 开发库
- **编译方式**: Makefile / CMake

---

## 3. 扩展属性定义

### 3.1 对象类

新增对象类 `pwdPolicyExtension`：

``` LDIF
objectClass ( 1.3.6.1.4.1.XXXX.1
    NAME 'pwdPolicyExtension'
    DESC 'Password Policy Extension'
    SUP top
    STRUCTURAL
    MUST ( cn )
    MAY ( pwdMaxLength $ pwdCharSet $ pwdNoUserCheck $ pwdForbiddenStrings ) )
```

### 3.2 属性定义

#### pwdMaxLength

- **OID**: 1.3.6.1.4.1.XXXX.1.1
- **语法**: 整数
- **默认值**: 0（表示不限制）
- **说明**: 密码最大长度限制

#### pwdCharSet

- **OID**: 1.3.6.1.4.1.XXXX.1.2
- **语法**: 整数
- **默认值**: 0
- **说明**: 字符集选项位标志

| 位 | 值 | 含义 |
|----|-----|------|
| Bit 0 | 1 | 必须包含大写字母 (A-Z) |
| Bit 1 | 2 | 必须包含小写字母 (a-z) |
| Bit 2 | 4 | 必须包含数字 (0-9) |
| Bit 3 | 8 | 必须包含特殊字符 |

**示例**: `pwdCharSet: 7` = 1+2+4，表示必须包含大写、小写和数字

#### pwdNoUserCheck

- **OID**: 1.3.6.1.4.1.XXXX.1.3
- **语法**: 布尔
- **默认值**: FALSE
- **说明**: 是否禁止密码包含用户名

#### pwdForbiddenStrings

- **OID**: 1.3.6.1.4.1.XXXX.1.4
- **语法**: 字符串
- **默认值**: 空
- **说明**: 逗号分隔的黑名单字符串列表

---

## 4. 配置示例

### 4.1 密码策略条目

``` LDIF
dn: cn=default,ou=pwpolicies,dc=example,dc=com
objectClass: top
objectClass: pwdPolicy
objectClass: pwdPolicyExtension
cn: default
desc: Default password policy

# === 原生属性 ===
pwdMinLength: 8
pwdMaxAge: 7776000
pwdMinAge: 0
pwdExpireWarning: 1296000
pwdInHistory: 1
pwdMustChange: FALSE

# === 扩展属性 ===
pwdMaxLength: 64
pwdCharSet: 7
pwdNoUserCheck: TRUE
pwdForbiddenStrings: weak,password123,admin,123456,letmein,iloveyou
```

### 4.2 用户条目引用策略

``` LDIF
dn: uid=test,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
objectClass: pwdPolicy
uid: test
cn: Test User
sn: User
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/test
pwdPolicySubentry: cn=default,ou=pwpolicies,dc=example,dc=com
```

---

## 5. 功能实现

### 5.1 pwdMaxLength 检查

**逻辑**:
```c
if (pwdMaxLength > 0 && password_length > pwdMaxLength) {
    return LDAP_CONSTRAINTViolation;
}
```

### 5.2 pwdCharSet 检查

**逻辑**:
```c
if (pwdCharSet & 1) {  // 需要大写
    if (!has_uppercase(password)) return LDAP_CONSTRAINTViolation;
}
if (pwdCharSet & 2) {  // 需要小写
    if (!has_lowercase(password)) return LDAP_CONSTRAINTViolation;
}
if (pwdCharSet & 4) {  // 需要数字
    if (!has_digit(password)) return LDAP_CONSTRAINTViolation;
}
if (pwdCharSet & 8) {  // 需要特殊字符
    if (!has_special(password)) return LDAP_CONSTRAINTViolation;
}
```

### 5.3 pwdNoUserCheck 检查

**逻辑**:
```c
if (pwdNoUserCheck == TRUE) {
    // 获取用户的 uid, cn, sn 等属性值
    // 检查密码是否包含任意一个值
    for (each attr in [uid, cn, sn, givenName]) {
        if (attr_value != NULL && strcasestr(password, attr_value) != NULL) {
            return LDAP_CONSTRAINTViolation;
        }
    }
}
```

### 5.4 pwdForbiddenStrings 检查

**逻辑**:
```c
if (pwdForbiddenStrings != NULL && password != NULL) {
    // 按逗号分隔黑名单
    tokens = split(pwdForbiddenStrings, ",");
    for (each token in tokens) {
        trim_space(token);
        if (strcasestr(password, token) != NULL) {
            return LDAP_CONSTRAINTViolation;
        }
    }
}
```

---

## 6. 错误处理

### 6.1 错误码

| 错误类型 | LDAP 错误码 | 说明 |
|----------|-------------|------|
| 密码太长 | `LDAP_CONSTRAINT_VIOLATION` | 超过 `pwdMaxLength` |
| 字符集不满足 | `LDAP_CONSTRAINT_VIOLATION` | 不满足 `pwdCharSet` 要求 |
| 密码包含用户名 | `LDAP_CONSTRAINT_VIOLATION` | 违反 `pwdNoUserCheck` |
| 密码在黑名单中 | `LDAP_CONSTRAINT_VIOLATION` | 包含 `pwdForbiddenStrings` 中的字符串 |

### 6.2 错误消息

通过 `slapd.conf` 或 `cn=config` 配置错误消息返回格式。

---

## 7. 性能考虑

1. **黑名单检查优化**: 对于大量黑名单词条，考虑使用 Trie 树或哈希集合存储
2. **延迟加载**: 策略配置在模块初始化时读取，缓存于内存
3. **增量检查**: 各检查项独立执行，遇到首个失败即返回

---

## 8. 目录结构

```
ppolicy-extensions/
├── docs/
│   └── ppolicy-overlay-design.md      # 本文档
├── include/
│   └── ppolicy_ext.h                  # 头文件
├── src/
│   ├── module.c                        # 模块入口
│   ├── check_maxlength.c               # 最大长度检查
│   ├── check_charset.c                 # 字符集检查
│   ├── check_user.c                    # 用户名包含检查
│   └── check_forbidden.c                # 黑名单检查
├── schema/
│   └── ppolicy-extension.schema        # schema 定义
├── tests/
│   └── test_ppolicy.c                  # 单元测试
├── Makefile
└── README.md
```

---

## 9. 依赖项

- OpenLDAP 2.4+
- OpenLDAP 开发库 (`ldap.h`, `lutil.h`)
- C 编译器 (gcc/clang)
- POSIX 标准库

---

## 10. 验证状态

| 策略项 | 状态 | 说明 |
|--------|------|------|
| pwdMaxLength | 待实现 | 可配置 |
| pwdCharSet | 待实现 | 可配置 |
| pwdNoUserCheck | 待实现 | 可配置 |
| pwdForbiddenStrings | 待实现 | 可配置 |

---

## 11. 后续工作

1. 编写 `pwdPolicyExtension` 对象类和属性 OID 分配
2. 实现 pw-quality 模块框架
3. 实现各检查函数
4. 编写 Makefile 和构建脚本
5. 编写单元测试
6. 编写 README 部署文档

---

*文档版本: 1.0*
*创建日期: 2026-03-20*
