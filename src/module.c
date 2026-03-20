#include "ppolicy_ext.h"
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
