# ppolicy-extensions 项目技术介绍

## 一句话概括

这个项目是一个 **C 语言共享库**（`.so` 文件），它被 OpenLDAP 服务器（`slapd`）在运行时动态加载，每当用户修改密码时，OpenLDAP 会调用这个库里的函数来检查密码是否符合自定义规则。

## 运行全景图

```
用户修改密码（ldappasswd / ldapmodify）
        │
        ▼
┌─────────────────────────────┐
│     OpenLDAP 服务器 (slapd)   │
│                               │
│  slapo-ppolicy overlay        │  ← OpenLDAP 内置的密码策略模块
│       │                       │
│       │ dlopen() 动态加载      │  ← 类似"插件机制"
│       ▼                       │
│  ┌─────────────────────┐      │
│  │ ppolicy_ext.so      │      │  ← 就是本项目编译出来的文件
│  │                     │      │
│  │ check_password()    │      │  ← OpenLDAP 约定的入口函数
│  │   ├─ 最大长度检查    │      │
│  │   ├─ 字符集检查      │      │
│  │   ├─ 用户名包含检查  │      │
│  │   └─ 黑名单检查      │      │
│  └─────────────────────┘      │
│       │                       │
│       ▼                       │
│  返回 OK 或 拒绝（含错误原因） │
└─────────────────────────────┘
```

## 关键概念解释

### 1. 什么是共享库（`.so` 文件）

在 C 语言中，代码可以编译成两种形式：
- **可执行文件**：可以直接运行（比如 `./my_program`）
- **共享库**（`.so`）：不能直接运行，而是被其他程序在运行时加载使用

本项目编译产物是 `lib/ppolicy_ext.so`，它**不是一个独立程序**，而是一个"插件"，由 OpenLDAP 在需要时加载。

### 2. 入口函数 `check_password`

OpenLDAP 的密码策略模块（slapo-ppolicy）有一个约定：插件必须提供一个叫 `check_password` 的函数，签名如下（`src/check_password.c:177`）：

```c
int check_password(char *pPasswd, struct berval *pErrmsg, Entry *pEntry, struct berval *pArg);
```

四个参数含义：

| 参数 | 类型 | 含义 |
|------|------|------|
| `pPasswd` | `char*` | 用户输入的新密码 |
| `pErrmsg` | `struct berval*` | 输出参数，检查失败时填入错误信息 |
| `pEntry` | `Entry*` | 用户的 LDAP 条目（包含 DN、uid 等信息） |
| `pArg` | `struct berval*` | 策略配置参数（来自 LDAP 的 `pwdCheckModuleArg` 属性） |

这个函数就是"一切的起点"——OpenLDAP 每次需要验证密码时，就会调用它。

### 3. 代码执行流程（逐步拆解）

当 `check_password` 被调用后，按以下顺序执行：

**第一步：初始化上下文**（`src/module.c`）

```c
ppolicy_ext_init(&ctx);
```

用 `calloc` 分配一块内存，创建一个 `ppolicy_ext_ctx_t` 结构体。`calloc` 会自动把内存清零，这比 `malloc` 更安全。

**第二步：加载策略配置**（`src/check_password.c:200-213`）

策略定义了"密码需要满足哪些规则"。策略通过 `pArg`（LDAP 存储的配置）传递，格式如 `extPwdMaxLength=32 extPwdCharSet=15`。如果没有 `pArg`，模块跳过所有检查（无约束）。

解析后得到一个 `pwd_policy_extension_t` 结构体：

```c
typedef struct pwd_policy_extension {
    int   pwd_max_length;        // 密码最大长度，0=不限制
    int   pwd_char_set;          // 字符集要求（位标志）
    int   pwd_no_user_check;     // 是否禁止密码包含用户名
    char* pwd_forbidden_strings; // 黑名单（逗号分隔）
} pwd_policy_extension_t;
```

**第三步：构建用户上下文**（`src/check_password.c:216-235`）

从 `pEntry` 中提取用户 DN（Distinguished Name，类似用户路径），再从 DN 中提取 `uid`（用户名）。比如：

```
DN: uid=zhangsan,ou=people,dc=example,dc=com
              ↓ extract_uid_from_dn()
uid: zhangsan
```

**第四步：执行密码检查**（`src/check.c`，核心逻辑）

```c
int ppolicy_ext_check_password(ctx, user, policy) {
    // 1. 最大长度检查
    // 2. 字符集检查
    // 3. 用户名包含检查
    // 4. 黑名单检查
}
```

采用 **fail-fast**（快速失败）策略：任何一个检查不通过，立即返回错误码，不再执行后续检查。

### 4. 四个验证器详解

**最大长度检查**（`src/check_maxlength.c`）— 最简单的验证器：

```c
if (max_length > 0 && length > max_length) {
    return PWD_CHECK_MAX_LENGTH;  // 密码太长了
}
return PWD_CHECK_OK;             // 通过
```

**字符集检查**（`src/check_charset.c`）— 使用**位标志**：

```
pwd_char_set 的值是一个整数，每一位代表一种字符类型：
  bit 0 (值1): 必须包含大写字母   A-Z
  bit 1 (值2): 必须包含小写字母   a-z
  bit 2 (值4): 必须包含数字       0-9
  bit 3 (值8): 必须包含特殊字符   !@#等

例如：char_set = 7 = 0b0111 → 要求大写 + 小写 + 数字
例如：char_set = 15 = 0b1111 → 全部都要求
```

用 `&`（按位与）来判断某个位是否为 1：

```c
if (char_set & 1) { /* 检查是否有大写 */ }
if (char_set & 2) { /* 检查是否有小写 */ }
```

**用户名包含检查**（`src/check_user.c`）：密码中不能包含用户名、姓名等（不区分大小写）。

**黑名单检查**（`src/check_forbidden.c`）：密码中不能包含黑名单中的任何字符串，如 `"weak,admin,password"` 中的任何一个。

## 编译过程

`Makefile` 定义了编译步骤：

```
源码 (.c)  →  编译  →  目标文件 (.o)  →  链接  →  共享库 (.so)

src/check.c          build/check.o
src/module.c   gcc   build/module.o   gcc -shared   lib/ppolicy_ext.so
src/policy.c  ──→    build/policy.o  ──────────→   （最终产物）
...                  ...
```

关键编译参数：
- `-Wall -Wextra`：开启所有警告，帮助发现潜在问题
- `-fPIC`：生成位置无关代码（Position Independent Code），共享库必须用这个选项
- `-shared`：告诉链接器生成 `.so` 而不是可执行文件

## 测试机制

以 `tests/unit/test_check_maxlength.c` 为例：

```c
void test_check_max_length_ok() {
    // "password123" 长度是11，限制是64，应该通过
    assert(ppolicy_check_max_length("password123", 11, 64) == PWD_CHECK_OK);
}

int main() {
    test_check_max_length_ok();      // 如果 assert 失败，程序立即崩溃退出
    test_check_max_length_fail();
    test_check_max_length_no_limit();
    printf("All maxlength tests passed!\n");  // 能走到这里说明全部通过
    return 0;
}
```

每个测试文件是一个独立的可执行程序，`make test` 会逐个编译、运行、然后删除。没有使用测试框架，而是用 C 标准库的 `assert()` — 条件为假时程序直接终止。

## 项目目录结构

```
.
├── Makefile                         # 编译脚本
├── include/
│   ├── ldap.h                       # LDAP 类型 mock（无 libldap 时使用）
│   └── ppolicy_ext.h                # 主头文件：结构体、枚举、函数声明
├── src/
│   ├── module.c                     # 模块初始化/销毁
│   ├── policy.c                     # 从 LDAP 加载策略配置
│   ├── check.c                      # 密码检查主入口（串联所有验证器）
│   ├── check_password.c             # OpenLDAP 调用的入口函数 check_password
│   ├── check_maxlength.c            # 验证器：最大长度
│   ├── check_charset.c              # 验证器：字符集
│   ├── check_user.c                 # 验证器：用户名包含
│   ├── check_forbidden.c            # 验证器：黑名单
│   └── utils.c                      # 工具函数
├── lib/
│   └── ppolicy_ext.so               # 编译产物（共享库）
├── tests/
│   ├── unit/                        # 单元测试
│   └── integration/                 # 集成测试
├── schema/
│   └── ppolicy-extension.schema     # LDAP Schema 定义
├── config/                          # slapd 配置文件
└── docs/                            # 文档
```

## 代码调用关系图

```
check_password()                  ← OpenLDAP 调用的入口
  ├── ppolicy_ext_init()          ← 分配内存，初始化上下文
  ├── load_policy_from_arg()      ← 从 LDAP 属性解析策略配置
  │     或 load_policy_from_conf()← 从配置文件读取（回退方案）
  ├── extract_uid_from_dn()       ← 从 DN 提取用户名
  ├── ppolicy_ext_check_password()← 执行所有检查（fail-fast）
  │     ├── ppolicy_check_max_length()
  │     ├── ppolicy_check_charset()
  │     ├── ppolicy_check_no_user()
  │     └── ppolicy_check_forbidden()
  ├── ppolicy_format_error()      ← 失败时格式化错误信息
  └── ppolicy_ext_destroy()       ← 释放内存，清理资源
```

整个项目的设计非常清晰：**每个验证器独立一个 `.c` 文件，互不依赖，通过 `check.c` 串联调用**。如果要添加新的密码规则，只需要新增一个验证器文件，然后在 `check.c` 中加一行调用即可。
