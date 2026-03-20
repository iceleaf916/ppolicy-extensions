# ppolicy-extensions 开发指南

## 1. 项目概述

`ppolicy-extensions` 是一个 OpenLDAP 密码策略扩展模块，基于原生 `slapo-ppolicy` overlay 实现额外的密码验证功能。

### 扩展功能

| 功能 | 属性 | 说明 |
|------|------|------|
| 密码最大长度 | `pwdMaxLength` | 限制密码最大字符数 |
| 字符集复杂度 | `pwdCharSet` | 大写/小写/数字/特殊字符组合要求 |
| 用户名检查 | `pwdNoUserCheck` | 禁止密码包含用户名 |
| 黑名单检查 | `pwdForbiddenStrings` | 禁止密码包含特定字符串 |

---

## 2. 开发环境

### 2.1 依赖项

- OpenLDAP 2.4+ 开发库 (`libldap-dev`)
- GCC / Clang 编译器
- GNU Make
- Docker

### 2.2 Docker 构建环境（推荐）

#### 编译环境镜像

```bash
# 一键构建（编译模块）
./build-docker.sh

# 进入开发环境 shell
./build-docker-shell.sh

# 手动构建编译环境镜像
docker build -t ppolicy-extensions-builder -f Dockerfile .

# 在编译环境容器中编译
docker run --rm -v $(pwd):/workspace/ppolicy-extensions ppolicy-extensions-builder make clean all
```

容器内已安装所有依赖：
- `slapd` - OpenLDAP 服务器
- `libldap-dev` - LDAP 开发库
- `ldap-utils` - LDAP 工具
- `build-essential` - 编译工具链

#### OpenLDAP 服务镜像

构建包含 OpenLDAP + ppolicy-extensions 的完整服务镜像：

```bash
# 构建 OpenLDAP 服务镜像
docker build -t ppolicy-openldap:latest -f Dockerfile.openldap .

# 启动 OpenLDAP 服务
docker run -d --name ppolicy-openldap -p 389:389 ppolicy-openldap:latest

# 查看服务日志
docker logs ppolicy-openldap

# 进入容器内操作
docker exec -it ppolicy-openldap bash

# 测试 LDAP 连接
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

### 2.3 本地构建（无 Docker）

确保已安装 OpenLDAP 开发包：

```bash
# Ubuntu/Debian
sudo apt-get install slapd libldap-dev ldap-utils build-essential make

# 使用 mock ldap.h 编译（仅测试用）
make
```

---

## 3. 项目结构

```
ppolicy-extensions/
├── Dockerfile              # 编译环境 Docker 镜像
├── Dockerfile.openldap      # OpenLDAP 服务镜像
├── docker-compose.yml      # 编译环境 Docker Compose 配置
├── docker-compose.openldap.yml  # OpenLDAP 服务配置
├── Makefile                 # 主构建文件
├── Makefile.docker          # Docker 构建辅助命令
├── build-docker.sh          # 编译环境一键构建脚本
├── build-docker-shell.sh    # 进入编译环境 shell 脚本
│
├── config/
│   ├── slapd.conf           # slapd 配置文件
│   └── init-data.ldif       # OpenLDAP 初始化数据
│
├── include/
│   └── ppolicy_ext.h       # 头文件，定义所有 API 和数据结构
│
├── src/                     # 源代码
│   ├── module.c             # 模块初始化/销毁
│   ├── check.c              # 主检查入口，调用各检查函数
│   ├── check_maxlength.c    # 密码最大长度检查
│   ├── check_charset.c      # 字符集复杂度检查
│   ├── check_user.c         # 用户名包含检查
│   ├── check_forbidden.c    # 黑名单字符串检查
│   ├── policy.c             # 策略加载
│   └── utils.c              # 工具函数
│
├── mock/
│   └── ldap.h               # Mock LDAP 头文件（无 libldap 时使用）
│
├── schema/
│   └── ppolicy-extension.schema  # LDAP Schema 定义
│
├── tests/unit/              # 单元测试
│   ├── test_utils.c
│   ├── test_check_maxlength.c
│   ├── test_check_charset.c
│   ├── test_check_user.c
│   ├── test_check_forbidden.c
│   └── test_policy.c
│
└── docs/
    ├── development-guide.md  # 本文档
    ├── testing-guide.md      # 测试指南
    ├── ppolicy-overlay-design.md
    └── ppolicy-overlay-detailed-design.md
```

---

## 4. 编译构建

### 4.1 Docker 构建（推荐）

#### 构建编译环境镜像

```bash
# 方式1: 一键构建脚本
./build-docker.sh

# 方式2: 手动构建
docker build -t ppolicy-extensions-builder -f Dockerfile .

# 方式3: 使用 docker-compose
docker-compose -f docker-compose.yml up -d --build
docker-compose exec builder make all
```

#### 构建 OpenLDAP 服务镜像

```bash
# 构建完整服务镜像（包含 OpenLDAP + 扩展模块）
docker build -t ppolicy-openldap:latest -f Dockerfile.openldap .

# 启动服务
docker run -d --name ppolicy-openldap -p 389:389 ppolicy-openldap:latest

# 查看状态
docker ps | grep ppolicy-openldap
```

### 4.2 本地编译

```bash
# 清理并重新编译
make clean
make

# 仅编译
make all

# 运行测试
make test

# 安装
sudo make install
```

### 4.3 Docker Compose 常用命令

```bash
# 启动编译环境
docker-compose up -d builder

# 进入编译环境 shell
docker-compose exec builder bash

# 在容器中编译
docker-compose exec builder make clean all

# 在容器中运行测试
docker-compose exec builder make test

# 停止服务
docker-compose down

# 查看日志
docker-compose logs -f builder
```

### 4.4 编译产物

| 文件 | 说明 |
|------|------|
| `lib/ppolicy_ext.so` | 编译生成的共享库 |
| `build/*.o` | 目标文件 |

---

## 5. 代码规范

### 5.1 命名约定

- **类型名**: `pwd_xxx_t` 或 `ppolicy_xxx_t` (小写下划线分隔)
- **函数名**: `ppolicy_xxx_yyy()` (模块前缀 + 下划线分隔)
- **常量/枚举**: `PWD_XXX_YYY` (全大写下划线分隔)
- **变量名**: `xxx_yyy` (小写下划线分隔)

### 5.2 函数返回值

| 类型 | 返回值 | 说明 |
|------|--------|------|
| 初始化函数 | `int` | 0=成功, -1=失败 |
| 检查函数 | `pwd_check_result_t` | `PWD_CHECK_OK`=通过, 其他=失败原因 |
| 工具函数 | `int` 或 `char*` | 根据功能决定 |

### 5.3 错误处理

- 所有返回指针的函数失败时返回 `NULL`
- 内存分配使用 `calloc`/`malloc`，失败时返回 `NULL`
- 字符串参数为 `NULL` 时应进行防御性检查
- 资源释放注意空指针保护

---

## 6. 扩展开发

### 6.1 添加新检查项

1. **在头文件中声明** (`include/ppolicy_ext.h`):

```c
typedef enum pwd_check_result {
    // ... 现有项
    PWD_CHECK_NEW_ITEM = 8  // 新检查项
} pwd_check_result_t;

// 声明函数
pwd_check_result_t ppolicy_check_new_item(
    const char* password,
    int         param
);
```

2. **实现检查函数** (`src/check_new_item.c`):

```c
#include "ppolicy_ext.h"

pwd_check_result_t ppolicy_check_new_item(
    const char* password,
    int         param
) {
    if (!password) {
        return PWD_CHECK_OK;
    }

    // 实现检查逻辑...

    return PWD_CHECK_OK;
}
```

3. **在 `check.c` 中调用**:

```c
// 在 ppolicy_ext_check_password 函数中添加
result = ppolicy_check_new_item(password, policy->new_param);
if (result != PWD_CHECK_OK) {
    return result;
}
```

4. **添加单元测试** (`tests/unit/test_new_item.c`):

```c
#include <assert.h>
#include "ppolicy_ext.h"

void test_new_item_normal() {
    pwd_check_result_t result = ppolicy_check_new_item("password", 1);
    assert(result == PWD_CHECK_OK);
}

int main() {
    test_new_item_normal();
    return 0;
}
```

5. **在 Makefile 中注册** (如需独立编译):

```makefile
SRC = ... src/check_new_item.c
```

### 6.2 添加新配置属性

1. **在 Schema 中定义** (`schema/ppolicy-extension.schema`):

```schema
attributetype ( 1.3.6.1.4.1.XXXX.1.X
    NAME 'pwdNewAttr'
    DESC 'New attribute description'
    EQUALITY caseExactMatch
    SUBSTR caseExactSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
```

2. **在对象类中添加** (同一 schema 文件):

```schema
objectClass ( 1.3.6.1.4.1.XXXX.1
    NAME 'pwdPolicyExtension'
    DESC 'Password Policy Extension'
    SUP top
    STRUCTURAL
    MUST ( cn )
    MAY ( ... $ pwdNewAttr ) )
```

3. **在头文件中添加结构体字段**:

```c
typedef struct pwd_policy_extension {
    // ... 现有字段
    char* pwd_new_attr;  // 新属性
} pwd_policy_extension_t;
```

---

## 7. 测试

### 7.1 运行单元测试

```bash
# 在 Docker 环境中
docker-compose exec builder make test

# 本地运行
make test
```

### 7.2 测试覆盖项

| 测试文件 | 测试内容 |
|----------|----------|
| `test_utils.c` | 工具函数测试 |
| `test_check_maxlength.c` | 密码最大长度检查 |
| `test_check_charset.c` | 字符集检查 |
| `test_check_user.c` | 用户名包含检查 |
| `test_check_forbidden.c` | 黑名单检查 |
| `test_policy.c` | 策略加载测试 |

### 7.3 编写新测试

```bash
# 编译并运行单个测试
gcc $(CFLAGS) -o test_xxx tests/unit/test_xxx.c src/xxx.c src/utils.c
./test_xxx
rm -f test_xxx
```

---

## 8. 调试

### 8.1 在 Docker 中调试

#### 调试编译问题

```bash
# 进入编译环境
docker run -it --rm \
  -v $(pwd):/workspace/ppolicy-extensions \
  ppolicy-extensions-builder bash

# 在容器内手动编译
cd /workspace/ppolicy-extensions
make clean
make all
```

#### 调试 OpenLDAP 服务

```bash
# 以调试模式启动 slapd
docker run --rm -it \
  -p 389:389 \
  ppolicy-openldap:latest \
  /usr/sbin/slapd -h "ldap://0.0.0.0:389/" \
  -f /etc/ldap/slapd.conf \
  -u openldap -g openldap \
  -d 255

# 参数说明:
# -d 255: 最高调试级别
# -d 1:   只输出连接和操作日志
# -d 0:   静默模式
```

#### 在运行中的容器内调试

```bash
# 进入运行中的容器
docker exec -it ppolicy-openldap bash

# 检查 slapd 进程
ps aux | grep slapd

# 查看 slapd 日志/输出
# (默认输出到 stdout，在 docker logs 中查看)

# 测试 LDAP 查询
ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" -w admin123

# 使用 ldapwhoami 验证绑定
ldapwhoami -x -H ldap://localhost:389 \
  -D "uid=testuser,ou=people,dc=example,dc=com" -w Test@1234
```

### 8.2 GDB 调试

```bash
# 编译带调试信息
gcc -g -Wall -Wextra -I./include -fPIC -c src/check.c -o build/check.o

# 在 Docker 中调试
docker-compose exec builder bash
gdb --args slapd -d 255 -f /etc/ldap/slapd.conf
```

### 8.3 日志输出

OpenLDAP 模块通过 `Debug()` 宏输出日志：

```c
#include <ldap_log.h>

Debug(LDAP_DEBUG_ANY, "ppolicy_ext: error message %s\n", arg);
```

调试级别常量：
- `LDAP_DEBUG_TRACE` - 跟踪信息
- `LDAP_DEBUG_DEBUG` - 调试信息
- `LDAP_DEBUG_ANY` - 错误信息

### 8.4 验证扩展模块

```bash
# 验证扩展 schema 已加载
ldapsearch -x -H ldap://localhost:389 \
  -b "cn=default,ou=pwpolicies,dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" -w admin123 -s base

# 检查扩展属性
# 应该显示 extPwdMaxLength, extPwdCharSet, extPwdNoUserCheck, extPwdForbiddenStrings

# 验证库文件存在
docker exec ppolicy-openldap ls -la /workspace/ppolicy-extensions/lib/
```

---

## 9. 常见问题

### 9.1 编译错误: `ldap.h: No such file`

```bash
# 安装 OpenLDAP 开发库
sudo apt-get install libldap-dev
```

### 9.2 链接错误: `undefined reference to ldap_*`

确保 `libldap-dev` 已安装，或使用 Docker 环境编译。

### 9.3 Docker 构建失败

```bash
# 清理 Docker 构建缓存重新构建
docker build --no-cache -t ppolicy-openldap:latest -f Dockerfile.openldap .

# 检查 Docker 是否运行
docker ps

# 查看 Docker 日志
docker logs ppolicy-openldap
```

### 9.4 容器启动后立即退出

```bash
# 查看退出原因
docker logs ppolicy-openldap

# 以前台模式启动查看错误
docker run --rm -it ppolicy-openldap:latest bash
/usr/sbin/slapd -h "ldap://0.0.0.0:389/" -f /etc/ldap/slapd.conf -u openldap -g openldap
```

### 9.5 LDAP 连接被拒绝

```bash
# 检查容器是否运行
docker ps | grep ppolicy-openldap

# 检查端口映射
docker port ppolicy-openldap 389

# 在容器内测试
docker exec ppolicy-openldap ldapsearch -x -H ldap://localhost:389 -b "" -s base
```

### 9.6 测试失败

检查 OpenLDAP 服务是否正常运行：
```bash
ldapsearch -x -ZZ -h localhost -b "" -s base
```

### 9.7 扩展属性未生效

确保扩展 schema 已正确加载：
```bash
# 查询密码策略配置
ldapsearch -x -H ldap://localhost:389 \
  -b "cn=default,ou=pwpolicies,dc=example,dc=com" \
  -D "cn=admin,dc=example,dc=com" -w admin123 -s base

# 检查是否显示 extPwdMaxLength 等属性
```

---

## 10. 相关文档

- [设计文档](ppolicy-overlay-design.md) - 项目设计概述
- [详细设计文档](ppolicy-overlay-detailed-design.md) - 完整技术细节
- [测试指南](testing-guide.md) - LDAP 服务功能测试
- [OpenLDAP 官方文档](https://www.openldap.org/doc/)
- [slapo-ppolicy man page](https://linux.die.net/man/5/slapo-ppolicy)
