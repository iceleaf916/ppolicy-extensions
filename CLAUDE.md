# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenLDAP 密码策略扩展模块（C 语言），作为 `slapo-ppolicy` overlay 的插件运行，提供额外的密码验证能力：最大长度、字符集复杂度、用户名包含检查、黑名单字符串。

## Build Commands

```bash
# 编译（本地需要 gcc、libldap-dev；无 libldap 时自动使用 include/ldap.h mock）
make clean && make

# 运行全部单元测试
make test

# 安装（目标：/opt/ppolicy-extensions/lib/ 和 /etc/openldap/schema/）
make install

# Docker 构建 OpenLDAP 测试环境（含编译 + slapd 服务）
docker build -t ppolicy-openldap:latest -f Dockerfile.openldap .
docker run -d --name ppolicy-openldap -p 389:389 ppolicy-openldap:latest

# 运行集成测试（需先启动上述容器）
bash tests/integration/test_ppolicy_integration.sh
```

没有独立的 lint 工具配置，编译已使用 `-Wall -Wextra`。

## Architecture

模块以共享库 `lib/ppolicy_ext.so` 形式输出，被 OpenLDAP 加载。

**核心数据流：**
1. `module.c` — 模块初始化/销毁（`ppolicy_ext_init` / `ppolicy_ext_destroy`）
2. `policy.c` — 从 LDAP 加载 `pwdPolicyExt` 条目中的扩展策略配置
3. `check.c` — 密码检查主入口 `ppolicy_ext_check_password`，按固定顺序调用各验证器，**fail-fast**（首个失败立即返回）
4. 验证器（各自独立，无耦合）：
   - `check_maxlength.c` → 最大长度
   - `check_charset.c` → 字符集位标志（bit 0=大写, 1=小写, 2=数字, 3=特殊字符）
   - `check_user.c` → 密码不得包含用户名等属性
   - `check_forbidden.c` → 逗号分隔的黑名单匹配

**关键类型定义（`include/ppolicy_ext.h`）：**
- `pwd_policy_extension_t` — 策略配置
- `pwd_user_context_t` — 用户上下文（DN、uid、密码等）
- `pwd_check_result_t` — 检查结果枚举

**添加新检查项的流程：** 在 `ppolicy_ext.h` 声明 → `src/` 下实现 → `check.c` 中调用 → 添加单元测试 → 更新 `schema/ppolicy-extension.schema`。

## Testing

单元测试在 `tests/unit/`，每个验证器对应一个测试文件。`make test` 逐个编译运行，测试二进制在运行后自动删除。无测试框架依赖，使用 `assert` 风格的自编写断手段。

功能测试需要 OpenLDAP 服务，参见 `docs/testing-guide.md`。可通过 `Dockerfile.openldap` 快速搭建。

## Mock Support

`include/ldap.h` 提供 LDAP 类型和常量的 mock 定义。当系统无 `libldap` 时，Makefile 不链接 `-lldap`，使用 mock 头文件即可编译和测试。
