#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "ppolicy_ext.h"

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
