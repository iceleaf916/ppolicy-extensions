# OpenLDAP ppolicy-extensions 测试指南

## 1. 环境准备

### 1.1 启动 OpenLDAP 服务

```bash
# 启动容器
docker run -d --name ppolicy-openldap -p 389:389 ppolicy-openldap:latest

# 验证服务状态
docker ps | grep ppolicy-openldap
```

### 1.2 安装 LDAP 客户端工具

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y ldap-utils

# CentOS/RHEL
sudo yum install -y openldap-clients
```

### 1.3 验证服务可用性

```bash
# 测试基本连接
ldapsearch -x -H ldap://localhost:389 -b "" -s base
```

预期输出：
```
# extended LDIF
...
dn:
objectClass: top
objectClass: OpenLDAProotDSE
...
```

---

## 2. 服务信息

| 项目 | 值 |
|------|-----|
| Base DN | `dc=example,dc=com` |
| Admin DN | `cn=admin,dc=example,dc=com` |
| Admin 密码 | `admin123` |
| LDAP 端口 | `389` |
| 测试用户 DN | `uid=testuser,ou=people,dc=example,dc=com` |
| 测试用户密码 | `Test@1234` |

---

## 3. 扩展属性说明

### 3.1 扩展属性列表

| 属性名 | 类型 | 说明 | 示例值 |
|--------|------|------|--------|
| `extPwdMaxLength` | 整数 | 密码最大长度，0表示不限制 | `64` |
| `extPwdCharSet` | 整数 | 字符集位标志 | `7` |
| `extPwdNoUserCheck` | 布尔 | 是否禁止密码包含用户名 | `TRUE` |
| `extPwdForbiddenStrings` | 字符串 | 黑名单字符串列表（逗号分隔） | `weak,password123` |

### 3.2 extPwdCharSet 位标志

| 位 | 值 | 含义 |
|----|-----|------|
| Bit 0 | 1 | 必须包含大写字母 (A-Z) |
| Bit 1 | 2 | 必须包含小写字母 (a-z) |
| Bit 2 | 4 | 必须包含数字 (0-9) |
| Bit 3 | 8 | 必须包含特殊字符 |

**示例**: `extPwdCharSet: 7` = 1+2+4，表示必须同时包含大写、小写和数字。

### 3.3 当前密码策略配置

密码策略存储在 `cn=default,ou=pwpolicies,dc=example,dc=com`：

```
extPwdMaxLength: 64          # 密码最长 64 字符
extPwdCharSet: 7              # 大写 + 小写 + 数字
extPwdNoUserCheck: TRUE       # 禁止密码包含用户名
extPwdForbiddenStrings: weak,password123,admin,123456,letmein,iloveyou,111111,qwerty
```

---

## 4. 功能测试

### 4.1 查询所有条目

```bash
ldapsearch -x -H ldap://localhost:389 \
  -b "dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" \
  -w admin123
```

### 4.2 查询密码策略配置

```bash
ldapsearch -x -H ldap://localhost:389 \
  -b "cn=default,ou=pwpolicies,dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" \
  -w admin123 -s base
```

预期输出：
```
# default, pwpolicies, example.com
dn: cn=default,ou=pwpolicies,dc=example,dc=com
objectClass: top
objectClass: pwdPolicyExt
cn: default
extPwdMaxLength: 64
extPwdCharSet: 7
extPwdNoUserCheck: TRUE
extPwdForbiddenStrings: weak,password123,admin,123456,letmein,iloveyou,111111,
 qwerty
```

### 4.3 测试用户绑定认证

```bash
# 使用测试用户绑定
ldapsearch -x -H ldap://localhost:389 \
  -b "uid=testuser,ou=people,dc=example,dc=com" \
  -D "uid=testuser,ou=people,dc=example,dc=com" \
  -w Test@1234
```

成功输出：
```
# testuser, people, example.com
dn: uid=testuser,ou=people,dc=example,dc=com
...
result: 0 Success
```

失败输出（密码错误）：
```
ldap_bind: Invalid credentials (49)
```

### 4.4 添加新用户

```bash
ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=com" \
  -w admin123 << EOF
dn: uid=newuser,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: New User
sn: User
uid: newuser
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/newuser
loginShell: /bin/bash
userPassword: Test@1234
EOF
```

成功输出：
```
adding new entry "uid=newuser,ou=people,dc=example,dc=com"
```

### 4.5 修改用户密码

```bash
# 使用 admin 修改用户密码
ldappasswd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=com" \
  -w admin123 \
  -s NewPass@1234 \
  "uid=newuser,ou=people,dc=example,dc=com"

# 用户修改自己的密码
ldappasswd -x -H ldap://localhost:389 \
  -D "uid=newuser,ou=people,dc=example,dc=com" \
  -w OldPass123 \
  -s NewPass@1234
```

### 4.6 删除用户

```bash
ldapdelete -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=com" \
  -w admin123 \
  "uid=newuser,ou=people,dc=example,dc=com"
```

---

## 5. 密码策略验证

### 5.1 验证 extPwdMaxLength

密码长度不能超过配置的最大值：

```bash
# 设置长密码（超过 64 字符）
ldappasswd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=com" -w admin123 \
  -s "ThisIsAVeryLongPasswordThatExceedsTheMaximumLengthOf64CharactersAndShouldBeRejectedByThePolicy" \
  "uid=testuser,ou=people,dc=example,dc=com"
```

**注意**：当前实现需要通过 slapo-ppolicy overlay 集成才能生效。

### 5.2 验证 extPwdForbiddenStrings

密码不能包含黑名单中的字符串：

```bash
# 尝试设置黑名单密码
ldappasswd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=example,dc=com" -w admin123 \
  -s "admin123" \
  "uid=testuser,ou=people,dc=example,dc=com"
```

**注意**：`admin123` 在黑名单中，应该被拒绝。

---

## 6. 常见问题

### 6.1 连接被拒绝

```bash
# 检查容器是否运行
docker ps | grep ppolicy-openldap

# 检查端口是否监听
docker exec ppolicy-openldap netstat -tlnp
```

### 6.2 认证失败

```
ldap_bind: Invalid credentials (49)
```

- 确认用户名/密码正确
- 确认 DN 格式正确

### 6.3 权限不足

```
ldap_add: Insufficient access (50)
```

- 需要使用 admin DN 进行需要管理员权限的操作
- 或检查 slapd.conf 中的 access 控制规则

---

## 7. 测试命令速查

```bash
# 启动服务
docker start ppolicy-openldap

# 停止服务
docker stop ppolicy-openldap

# 进入容器
docker exec -it ppolicy-openldap bash

# 查看日志
docker logs ppolicy-openldap

# 重启服务
docker restart ppolicy-openldap

# 测试连接
ldapsearch -x -H ldap://localhost:389 -b "" -s base

# 管理员查询所有
ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" -w admin123

# 查询密码策略
ldapsearch -x -H ldap://localhost:389 \
  -b "cn=default,ou=pwpolicies,dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" -w admin123 -s base
```

---

## 8. 清理环境

```bash
# 停止并删除容器
docker stop ppolicy-openldap
docker rm ppolicy-openldap

# 删除镜像（可选）
docker rmi ppolicy-openldap:latest
```
