#!/bin/bash
#
# ppolicy-extensions 集成测试
#
# 测试目标：验证 extPwdMaxLength / extPwdCharSet / extPwdNoUserCheck / extPwdForbiddenStrings
#           四个自定义扩展规则是否在 OpenLDAP 密码修改流程中生效。
#
# 前置条件：
#   docker build -t ppolicy-openldap:latest -f Dockerfile.openldap .
#   docker run -d --name ppolicy-openldap -p 389:389 ppolicy-openldap:latest
#
# 用法：
#   bash tests/integration/test_ppolicy_integration.sh [LDAP_HOST] [LDAP_PORT]
#
# 注意：
#   ppolicy overlay 不对 rootdn (admin) 执行策略检查，
#   因此策略执行测试使用**用户自改密码**方式进行。

set -euo pipefail

# ============================================================
# 配置
# ============================================================
LDAP_HOST="${1:-localhost}"
LDAP_PORT="${2:-389}"
LDAP_URI="ldap://${LDAP_HOST}:${LDAP_PORT}"

ADMIN_DN="cn=admin,dc=example,dc=com"
ADMIN_PW="admin123"
BASE_DN="dc=example,dc=com"
POLICY_DN="cn=default,ou=pwpolicies,dc=example,dc=com"

TEST_USER_DN="uid=testuser,ou=people,dc=example,dc=com"
TEST_USER_UID="testuser"
TEST_USER_PW="Test@1234"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 计数器
TOTAL=0
PASSED=0
FAILED=0
FAIL_DETAILS=()

# 当前 testuser 密码跟踪（自改密码成功后需要更新）
CURRENT_PW="$TEST_USER_PW"

# ============================================================
# 辅助函数
# ============================================================

log_section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# assert_success <test_name> <command...>
assert_success() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    local output
    if output=$("$@" 2>&1); then
        echo -e "  ${GREEN}✓${NC} ${name}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "  ${RED}✗${NC} ${name}"
        echo -e "    ${RED}输出: ${output}${NC}"
        FAILED=$((FAILED + 1))
        FAIL_DETAILS+=("${name}")
        return 1
    fi
}

# assert_fail <test_name> <command...>
assert_fail() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    local output
    if output=$("$@" 2>&1); then
        echo -e "  ${RED}✗${NC} ${name} (期望失败但成功了)"
        echo -e "    ${RED}输出: ${output}${NC}"
        FAILED=$((FAILED + 1))
        FAIL_DETAILS+=("${name}")
        return 1
    else
        echo -e "  ${GREEN}✓${NC} ${name}"
        PASSED=$((PASSED + 1))
        return 0
    fi
}

# assert_output_contains <test_name> <expected_substr> <command...>
assert_output_contains() {
    local name="$1"; shift
    local expected="$1"; shift
    TOTAL=$((TOTAL + 1))
    local output
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -qi "$expected"; then
        echo -e "  ${GREEN}✓${NC} ${name}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "  ${RED}✗${NC} ${name}"
        echo -e "    ${RED}期望包含: ${expected}${NC}"
        echo -e "    ${RED}实际输出: $(echo "$output" | head -3)${NC}"
        FAILED=$((FAILED + 1))
        FAIL_DETAILS+=("${name}")
        return 1
    fi
}

# ldap_search: 封装 ldapsearch
ldap_search() {
    ldapsearch -x -H "$LDAP_URI" -D "$ADMIN_DN" -w "$ADMIN_PW" "$@"
}

# self_passwd: 用户自改密码（会触发 ppolicy 检查）
self_passwd() {
    local new_pw="$1"
    ldappasswd -x -H "$LDAP_URI" \
        -D "$TEST_USER_DN" -w "$CURRENT_PW" \
        -s "$new_pw"
}

# admin_passwd: admin 改密码（绕过 ppolicy 检查，用于恢复密码）
admin_passwd() {
    local user_dn="$1"
    local new_pw="$2"
    ldappasswd -x -H "$LDAP_URI" \
        -D "$ADMIN_DN" -w "$ADMIN_PW" \
        -s "$new_pw" "$user_dn"
}

# reset_password: 用 admin 重置 testuser 密码到已知值
reset_password() {
    admin_passwd "$TEST_USER_DN" "$TEST_USER_PW" >/dev/null 2>&1
    CURRENT_PW="$TEST_USER_PW"
}

# 生成指定长度的重复字符串
gen_string() {
    local len=$1
    local char="${2:-A}"
    python3 -c "print('${char}' * ${len}, end='')"
}

# ============================================================
# 前置检查
# ============================================================

echo -e "${CYAN}ppolicy-extensions 集成测试${NC}"
echo "LDAP URI: ${LDAP_URI}"
echo ""

echo -n "检查 ldapsearch 命令... "
if ! command -v ldapsearch &>/dev/null; then
    echo -e "${RED}未找到！请安装 ldap-utils${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC}"

echo -n "检查 LDAP 服务连接... "
if ! ldapsearch -x -H "$LDAP_URI" -b "" -s base &>/dev/null; then
    echo -e "${RED}无法连接到 ${LDAP_URI}${NC}"
    exit 1
fi
echo -e "${GREEN}OK${NC}"

# ============================================================
# 第一部分：Schema 与策略数据验证
# ============================================================

log_section "1. Schema 与策略数据验证"

assert_output_contains \
    "1.1 pwdPolicyExt 对象类可查询" \
    "pwdPolicyExt" \
    ldap_search -b "$POLICY_DN" -s base "(objectClass=pwdPolicyExt)"

assert_output_contains \
    "1.2 pwdCheckModuleArg 包含 extPwdMaxLength=64" \
    "extPwdMaxLength=64" \
    ldap_search -b "$POLICY_DN" -s base pwdCheckModuleArg

assert_output_contains \
    "1.3 pwdCheckModuleArg 包含 extPwdCharSet=7" \
    "extPwdCharSet=7" \
    ldap_search -b "$POLICY_DN" -s base pwdCheckModuleArg

assert_output_contains \
    "1.4 pwdCheckModuleArg 包含 extPwdNoUserCheck=TRUE" \
    "extPwdNoUserCheck=TRUE" \
    ldap_search -b "$POLICY_DN" -s base pwdCheckModuleArg

assert_output_contains \
    "1.5 pwdCheckModuleArg 包含 ForbiddenStrings" \
    "ForbiddenStrings" \
    ldap_search -b "$POLICY_DN" -s base pwdCheckModuleArg

assert_output_contains \
    "1.6 pwdPolicy 原生对象类存在" \
    "pwdPolicy" \
    ldap_search -b "$POLICY_DN" -s base "(objectClass=pwdPolicy)"

assert_output_contains \
    "1.7 pwdCheckQuality 设为 2（强制检查）" \
    "pwdCheckQuality: 2" \
    ldap_search -b "$POLICY_DN" -s base pwdCheckQuality

assert_output_contains \
    "1.8 pwdUseCheckModule 设为 TRUE" \
    "pwdUseCheckModule: TRUE" \
    ldap_search -b "$POLICY_DN" -s base pwdUseCheckModule

# ============================================================
# 第二部分：基本 LDAP 操作验证
# ============================================================

log_section "2. 基本 LDAP 操作验证"

assert_success \
    "2.1 Admin 绑定认证成功" \
    ldap_search -b "$BASE_DN" -s base

assert_success \
    "2.2 testuser 绑定认证成功" \
    ldapsearch -x -H "$LDAP_URI" -D "$TEST_USER_DN" -w "$TEST_USER_PW" \
        -b "$TEST_USER_DN" -s base

assert_fail \
    "2.3 testuser 错误密码绑定失败" \
    ldapsearch -x -H "$LDAP_URI" -D "$TEST_USER_DN" -w "WrongPassword" \
        -b "$TEST_USER_DN" -s base

# ============================================================
# 第三部分：extPwdMaxLength 密码最大长度策略执行验证
# ============================================================

log_section "3. extPwdMaxLength — 密码最大长度策略执行验证"

# 当前策略: extPwdMaxLength=64

reset_password

# 3.1 合法：恰好 64 字符（满足字符集: 大写+小写+数字）
PW_64="$(gen_string 59 'K')aB1cd"  # 59 + 5 = 64
assert_success \
    "3.1 密码恰好 64 字符 — 应该接受" \
    self_passwd "$PW_64"
CURRENT_PW="$PW_64"

# 3.2 不合法：65 字符（超出最大长度）
PW_65="$(gen_string 60 'K')aB1cd"  # 60 + 5 = 65
assert_fail \
    "3.2 密码 65 字符（超出 maxLength=64）— 应该拒绝" \
    self_passwd "$PW_65"

# 3.3 不合法：128 字符（大幅超出）
PW_128="$(gen_string 123 'X')aB1cd"  # 123 + 5 = 128
assert_fail \
    "3.3 密码 128 字符 — 应该拒绝" \
    self_passwd "$PW_128"

# 3.4 合法：短密码（满足字符集）
reset_password
assert_success \
    "3.4 密码 8 字符 'Ab1efghX' — 应该接受" \
    self_passwd "Ab1efghX"
CURRENT_PW="Ab1efghX"

reset_password

# ============================================================
# 第四部分：extPwdCharSet 字符集复杂度策略执行验证
# ============================================================

log_section "4. extPwdCharSet — 字符集复杂度策略执行验证"

# 当前策略: extPwdCharSet=7 (bit0=大写 + bit1=小写 + bit2=数字)

reset_password

# 4.1 合法：包含大写+小写+数字
assert_success \
    "4.1 密码含大写+小写+数字 'Abc12345' — 应该接受" \
    self_passwd "Abc12345"
CURRENT_PW="Abc12345"

# 4.2 不合法：仅小写
assert_fail \
    "4.2 密码仅小写 'abcdefgh' — 应该拒绝（缺大写和数字）" \
    self_passwd "abcdefgh"

# 4.3 不合法：仅大写
assert_fail \
    "4.3 密码仅大写 'ABCDEFGH' — 应该拒绝（缺小写和数字）" \
    self_passwd "ABCDEFGH"

# 4.4 不合法：仅数字
assert_fail \
    "4.4 密码仅数字 '12345678' — 应该拒绝（缺大写和小写）" \
    self_passwd "12345678"

# 4.5 不合法：大写+小写，缺数字
assert_fail \
    "4.5 密码大写+小写无数字 'AbcdEfgh' — 应该拒绝" \
    self_passwd "AbcdEfgh"

# 4.6 不合法：大写+数字，缺小写
assert_fail \
    "4.6 密码大写+数字无小写 'ABCD1234' — 应该拒绝" \
    self_passwd "ABCD1234"

# 4.7 不合法：小写+数字，缺大写
assert_fail \
    "4.7 密码小写+数字无大写 'abcd1234' — 应该拒绝" \
    self_passwd "abcd1234"

# 4.8 合法：大写+小写+数字+特殊字符（超出要求也可以）
assert_success \
    "4.8 密码含大写+小写+数字+特殊字符 'Xbc123!@' — 应该接受" \
    self_passwd 'Xbc123!@'
CURRENT_PW='Xbc123!@'

# 4.9 不合法：纯特殊字符
assert_fail \
    "4.9 密码纯特殊字符 '!@#\$%^&*' — 应该拒绝" \
    self_passwd '!@#$%^&*'

reset_password

# ============================================================
# 第五部分：extPwdNoUserCheck 用户名检查策略执行验证
# ============================================================

log_section "5. extPwdNoUserCheck — 禁止密码包含用户名策略执行验证"

# 当前策略: extPwdNoUserCheck=TRUE
# testuser 的 uid=testuser

reset_password

# 5.1 不合法：密码包含用户名（大小写变体 — ppolicy_strcasestr 是不区分大小写的）
assert_fail \
    "5.1 密码包含用户名 'Testuser1' — 应该拒绝" \
    self_passwd "Testuser1"

# 5.2 不合法：密码包含用户名作为子串
assert_fail \
    "5.2 密码包含用户名 'My1testuser' — 应该拒绝" \
    self_passwd "My1testuser"

# 5.3 不合法：密码包含用户名（全大写）
assert_fail \
    "5.3 密码包含用户名 'TESTUSER1a' — 应该拒绝" \
    self_passwd "TESTUSER1a"

# 5.4 合法：密码不含用户名
assert_success \
    "5.4 密码不含用户名 'SecureP1ss' — 应该接受" \
    self_passwd "SecureP1ss"
CURRENT_PW="SecureP1ss"

reset_password

# ============================================================
# 第六部分：extPwdForbiddenStrings 黑名单策略执行验证
# ============================================================

log_section "6. extPwdForbiddenStrings — 黑名单字符串策略执行验证"

# 当前黑名单: weak,password123,admin,123456,letmein,iloveyou,111111,qwerty

reset_password

# 6.1 不合法：密码包含黑名单词 "admin"
assert_fail \
    "6.1 密码包含黑名单词 'SuperAdmin1' — 应该拒绝" \
    self_passwd "SuperAdmin1"

# 6.2 不合法：密码包含 "123456"
assert_fail \
    "6.2 密码包含黑名单词 'Abc123456' — 应该拒绝" \
    self_passwd "Abc123456"

# 6.3 不合法：密码包含 "letmein"
assert_fail \
    "6.3 密码包含黑名单词 'Letmein99' — 应该拒绝" \
    self_passwd "Letmein99"

# 6.4 不合法：密码包含 "iloveyou"
assert_fail \
    "6.4 密码包含黑名单词 'Iloveyou1' — 应该拒绝" \
    self_passwd "Iloveyou1"

# 6.5 不合法：密码包含 "111111"
assert_fail \
    "6.5 密码包含黑名单词 'Abc111111' — 应该拒绝" \
    self_passwd "Abc111111"

# 6.6 不合法：密码包含 "qwerty"
assert_fail \
    "6.6 密码包含黑名单词 'Qwerty99!' — 应该拒绝" \
    self_passwd "Qwerty99!"

# 6.7 不合法：密码包含 "password123"
assert_fail \
    "6.7 密码包含黑名单词 'Xpassword123' — 应该拒绝" \
    self_passwd "Xpassword123"

# 6.8 不合法：密码包含 "weak"
assert_fail \
    "6.8 密码包含黑名单词 'MyWeak1pw' — 应该拒绝" \
    self_passwd "MyWeak1pw"

# 6.9 合法：密码不含任何黑名单词
assert_success \
    "6.9 密码不含黑名单词 'Xk9mNvP3' — 应该接受" \
    self_passwd "Xk9mNvP3"
CURRENT_PW="Xk9mNvP3"

reset_password

# ============================================================
# 第七部分：组合场景验证
# ============================================================

log_section "7. 组合场景验证"

reset_password

# 7.1 同时违反多个策略：超长 + 无大写 + 含黑名单
PW_MULTI_BAD="$(gen_string 70 'a')weak"  # 74 chars, lowercase-only, contains 'weak'
assert_fail \
    "7.1 超长+无大写+含黑名单 — 应该拒绝" \
    self_passwd "$PW_MULTI_BAD"

# 7.2 满足所有策略的密码
assert_success \
    "7.2 满足全部策略 'V1lidPwd' — 应该接受" \
    self_passwd "V1lidPwd"
CURRENT_PW="V1lidPwd"

# 7.3 恰好边界值：64 字符 + 满足字符集
reset_password
PW_BOUNDARY="$(gen_string 59 'K')aB1xy"  # 59 + 5 = 64
assert_success \
    "7.3 边界值 64 字符且满足字符集 — 应该接受" \
    self_passwd "$PW_BOUNDARY"
CURRENT_PW="$PW_BOUNDARY"

# 7.4 密码含用户名 + 黑名单词
reset_password
assert_fail \
    "7.4 密码含用户名和黑名单词 'Testuser1weak' — 应该拒绝" \
    self_passwd "Testuser1weak"

# 恢复初始密码
reset_password

# ============================================================
# 第八部分：pwdCheckModuleArg 动态策略修改验证
# ============================================================

log_section "8. pwdCheckModuleArg — 动态策略修改验证"

# 保存原始策略值
ORIG_ARG="extPwdMaxLength=64 extPwdCharSet=7 extPwdNoUserCheck=TRUE extPwdForbiddenStrings=weak,password123,admin,123456,letmein,iloveyou,111111,qwerty"

# --- 8.1 动态修改 extPwdMaxLength: 64 -> 16 ---

ldapmodify -x -H "$LDAP_URI" -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null 2>&1 <<EOF
dn: $POLICY_DN
changetype: modify
replace: pwdCheckModuleArg
pwdCheckModuleArg: extPwdMaxLength=16 extPwdCharSet=7 extPwdNoUserCheck=TRUE extPwdForbiddenStrings=weak,admin
EOF

reset_password

# 17 字符密码 — 新策略(maxLength=16)下应拒绝
PW_17="$(gen_string 12 'K')aB1cd"  # 12 + 5 = 17
assert_fail \
    "8.1 动态改 maxLength=16 后，17 字符密码应被拒绝" \
    self_passwd "$PW_17"

# 16 字符密码 — 应接受
PW_16="$(gen_string 11 'K')aB1cd"  # 11 + 5 = 16
assert_success \
    "8.2 动态改 maxLength=16 后，16 字符密码应接受" \
    self_passwd "$PW_16"
CURRENT_PW="$PW_16"

# --- 8.3 动态修改后黑名单变化 ---

reset_password

# "qwerty" 之前在黑名单中，现已被移除，应接受
assert_success \
    "8.3 动态修改后 'qwerty' 不在黑名单 — 含 qwerty 应接受" \
    self_passwd "Qwerty9X"
CURRENT_PW="Qwerty9X"

# "admin" 仍在黑名单中，应拒绝
assert_fail \
    "8.4 动态修改后 'admin' 仍在黑名单 — 含 admin 应拒绝" \
    self_passwd "MyAdmin1X"

# --- 8.5 动态关闭用户名检查 ---

ldapmodify -x -H "$LDAP_URI" -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null 2>&1 <<EOF
dn: $POLICY_DN
changetype: modify
replace: pwdCheckModuleArg
pwdCheckModuleArg: extPwdMaxLength=64 extPwdCharSet=7 extPwdNoUserCheck=FALSE extPwdForbiddenStrings=weak,admin
EOF

reset_password

# extPwdNoUserCheck=FALSE 关闭用户名检查，含用户名应接受
assert_success \
    "8.5 动态关闭用户名检查后，含 testuser 应接受" \
    self_passwd "Testuser1X"
CURRENT_PW="Testuser1X"

# --- 8.6 动态修改字符集要求 ---

ldapmodify -x -H "$LDAP_URI" -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null 2>&1 <<EOF
dn: $POLICY_DN
changetype: modify
replace: pwdCheckModuleArg
pwdCheckModuleArg: extPwdMaxLength=64 extPwdCharSet=1 extPwdNoUserCheck=FALSE extPwdForbiddenStrings=weak,admin
EOF

reset_password

# extPwdCharSet=1 仅要求大写字母，纯大写应接受
assert_success \
    "8.6 动态改 charSet=1 后，纯大写密码应接受" \
    self_passwd "ABCDEFGH"
CURRENT_PW="ABCDEFGH"

# --- 恢复原始策略 ---

ldapmodify -x -H "$LDAP_URI" -D "$ADMIN_DN" -w "$ADMIN_PW" >/dev/null 2>&1 <<EOF
dn: $POLICY_DN
changetype: modify
replace: pwdCheckModuleArg
pwdCheckModuleArg: $ORIG_ARG
EOF

reset_password

# 8.7 恢复后验证原始策略仍有效：纯大写应拒绝（charSet=7 要求大写+小写+数字）
assert_fail \
    "8.7 恢复原始策略后，纯大写密码应拒绝" \
    self_passwd "ABCDEFGH"

# 8.8 恢复后验证：合法密码仍可接受
assert_success \
    "8.8 恢复原始策略后，合法密码 'V1lidPwd' 应接受" \
    self_passwd "V1lidPwd"
CURRENT_PW="V1lidPwd"

reset_password

# ============================================================
# 汇总
# ============================================================

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  测试结果汇总${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  总计: ${TOTAL}"
echo -e "  ${GREEN}通过: ${PASSED}${NC}"
echo -e "  ${RED}失败: ${FAILED}${NC}"

if [ ${#FAIL_DETAILS[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}失败的测试用例:${NC}"
    for detail in "${FAIL_DETAILS[@]}"; do
        echo -e "  ${RED}• ${detail}${NC}"
    done
fi

echo ""

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！四个扩展规则均已在 slapd 层面正确执行。${NC}"
    exit 0
else
    echo -e "${RED}有 ${FAILED} 个测试未通过。${NC}"
    exit 1
fi
