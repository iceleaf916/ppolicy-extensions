# ppolicy-extensions

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![OpenLDAP](https://img.shields.io/badge/OpenLDAP-2.4+-orange.svg)](https://www.openldap.org/)

OpenLDAP 密码策略扩展模块，基于原生 `slapo-ppolicy` overlay 实现可配置的密码验证功能。

## 功能特性

| 扩展属性 | 说明 | 示例 |
|----------|------|------|
| `extPwdMaxLength` | 密码最大长度限制 | `extPwdMaxLength: 64` |
| `extPwdCharSet` | 字符集复杂度要求 | `extPwdCharSet: 7` (大写+小写+数字) |
| `extPwdNoUserCheck` | 禁止密码包含用户名 | `extPwdNoUserCheck: TRUE` |
| `extPwdForbiddenStrings` | 黑名单字符串检查 | `extPwdForbiddenStrings: weak,123456` |

### extPwdCharSet 位标志

| 位 | 值 | 含义 |
|----|-----|------|
| Bit 0 | 1 | 必须包含大写字母 (A-Z) |
| Bit 1 | 2 | 必须包含小写字母 (a-z) |
| Bit 2 | 4 | 必须包含数字 (0-9) |
| Bit 3 | 8 | 必须包含特殊字符 |

**示例**: `extPwdCharSet: 7` = 1+2+4，表示必须同时包含大写、小写和数字。

---

## 快速开始

### 使用 Docker 运行 OpenLDAP 服务（推荐）

```bash
# 构建并启动 OpenLDAP 服务
docker build -t ppolicy-openldap:latest -f Dockerfile.openldap .
docker run -d --name ppolicy-openldap -p 389:389 ppolicy-openldap:latest

# 测试连接
ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" -w admin123
```

**服务信息：**

| 项目 | 值 |
|------|-----|
| Base DN | `dc=example,dc=com` |
| Admin DN | `cn=admin,dc=example,dc=com` |
| Admin 密码 | `admin123` |
| LDAP 端口 | `389` |
| 测试用户 | `uid=testuser,ou=people,dc=example,dc=com` |
| 测试用户密码 | `Test@1234` |

### 编译扩展模块

```bash
# 使用 Docker 编译
docker build -t ppolicy-extensions-builder -f Dockerfile .
docker run --rm -v $(pwd):/workspace/ppolicy-extensions ppolicy-extensions-builder make clean all

# 本地编译
sudo apt-get install slapd libldap-dev ldap-utils build-essential make
make clean && make

# 运行测试
make test
```

---

## 项目结构

```
ppolicy-extensions/
├── Dockerfile               # 编译环境 Docker 镜像
├── Dockerfile.openldap      # OpenLDAP 服务 Docker 镜像
├── docker-compose.yml       # 编译环境 Docker Compose 配置
├── docker-compose.openldap.yml  # OpenLDAP 服务 Docker Compose 配置
├── Makefile                 # 主构建文件
├── Makefile.docker          # Docker 构建辅助命令
├── build-docker.sh          # 编译环境一键构建脚本
│
├── config/
│   ├── slapd.conf           # slapd 配置文件
│   └── init-data.ldif       # OpenLDAP 初始化数据
│
├── include/
│   └── ppolicy_ext.h        # 头文件
├── src/
│   ├── module.c             # 模块初始化
│   ├── check.c              # 主检查入口
│   ├── check_maxlength.c    # 最大长度检查
│   ├── check_charset.c      # 字符集检查
│   ├── check_user.c         # 用户名检查
│   ├── check_forbidden.c     # 黑名单检查
│   ├── policy.c             # 策略加载
│   └── utils.c              # 工具函数
├── mock/
│   └── ldap.h               # Mock LDAP 头文件（无 libldap 时使用）
├── schema/
│   └── ppolicy-extension.schema  # LDAP Schema
├── tests/unit/              # 单元测试
│   ├── test_utils.c
│   ├── test_check_maxlength.c
│   ├── test_check_charset.c
│   ├── test_check_user.c
│   ├── test_check_forbidden.c
│   └── test_policy.c
└── docs/
    ├── development-guide.md  # 开发指南
    ├── testing-guide.md     # 测试指南
    └── ppolicy-overlay-design.md  # 设计文档
```

---

## 配置示例

### 密码策略 LDIF

```ldif
dn: cn=default,ou=pwpolicies,dc=example,dc=com
objectClass: top
objectClass: pwdPolicyExt
cn: default

# 扩展属性
extPwdMaxLength: 64
extPwdCharSet: 7          # 大写 + 小写 + 数字
extPwdNoUserCheck: TRUE
extPwdForbiddenStrings: weak,password123,admin,123456,letmein,iloveyou
```

### 用户条目引用策略

```ldif
dn: uid=test,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: test
cn: Test User
sn: User
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/test
userPassword: Test@1234
```

---

## API 概览

```c
// 模块初始化/销毁
int ppolicy_ext_init(ppolicy_ext_ctx_t** ctx);
void ppolicy_ext_destroy(ppolicy_ext_ctx_t* ctx);

// 密码检查主函数
int ppolicy_ext_check_password(
    ppolicy_ext_ctx_t*      ctx,
    pwd_user_context_t*     user,
    pwd_policy_extension_t* policy
);

// 策略加载
int ppolicy_ext_load_policy(
    LDAP*                   ld,
    const char*             policy_dn,
    pwd_policy_extension_t* policy
);
```

---

## 测试

```bash
# 运行所有单元测试
make test

# 测试覆盖
# - test_utils.c          # 工具函数
# - test_check_maxlength.c # 最大长度检查
# - test_check_charset.c   # 字符集检查
# - test_check_user.c      # 用户名检查
# - test_check_forbidden.c # 黑名单检查
# - test_policy.c          # 策略加载
```

---

## 扩展开发

### 添加新检查项

1. 在 `include/ppolicy_ext.h` 中声明新函数
2. 在 `src/` 下实现检查函数
3. 在 `check.c` 中调用
4. 添加单元测试
5. 更新 Schema 定义

详细开发信息请参考 [开发指南](docs/development-guide.md)。

---

## 常见问题

### 编译错误: `ldap.h: No such file`

```bash
sudo apt-get install libldap-dev
```

### Docker 构建失败

```bash
docker build -t ppolicy-openldap:latest -f Dockerfile.openldap .
docker logs ppolicy-openldap
```

### 使用 Mock 编译（无 OpenLDAP）

项目包含 `mock/ldap.h`，可直接编译用于测试：
```bash
make
```

---

## 相关文档

- [开发指南](docs/development-guide.md) - 详细的开发文档
- [测试指南](docs/testing-guide.md) - LDAP 服务功能测试
- [设计文档](docs/ppolicy-overlay-design.md) - 项目设计概述
- [详细设计文档](docs/ppolicy-overlay-detailed-design.md) - 完整技术细节

---

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

---

## 致谢

- [OpenLDAP](https://www.openldap.org/) - 开放源码 LDAP 目录服务
- 清华镜像源 - 中国大陆 apt 加速
