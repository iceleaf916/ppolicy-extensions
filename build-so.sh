#!/bin/bash
# 构建 Linux amd64 和 arm64 两个架构的 so 文件
# 使用 Docker buildx 多平台构建

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

OUTPUT_DIR="$SCRIPT_DIR/lib"
mkdir -p "$OUTPUT_DIR"

IMAGE_NAME="ppolicy-builder"
CONTAINER_NAME="ppolicy-build-$$"

echo "=== 构建 ppolicy_ext.so (amd64 + arm64) ==="

# 构建 amd64
echo ""
echo "--- [1/2] 构建 amd64 ---"
docker build --platform linux/amd64 -f Dockerfile.so-builder -t ${IMAGE_NAME}:amd64 .
docker create --name ${CONTAINER_NAME}-amd64 ${IMAGE_NAME}:amd64
docker cp ${CONTAINER_NAME}-amd64:/build/lib/ppolicy_ext_amd64.so "$OUTPUT_DIR/ppolicy_ext_amd64.so"
docker rm ${CONTAINER_NAME}-amd64
echo ">>> lib/ppolicy_ext_amd64.so"

# 构建 arm64
echo ""
echo "--- [2/2] 构建 arm64 ---"
docker build --platform linux/arm64 -f Dockerfile.so-builder -t ${IMAGE_NAME}:arm64 .
docker create --name ${CONTAINER_NAME}-arm64 ${IMAGE_NAME}:arm64
docker cp ${CONTAINER_NAME}-arm64:/build/lib/ppolicy_ext_arm64.so "$OUTPUT_DIR/ppolicy_ext_arm64.so"
docker rm ${CONTAINER_NAME}-arm64
echo ">>> lib/ppolicy_ext_arm64.so"

echo ""
echo "=== 构建完成 ==="
ls -lh "$OUTPUT_DIR"/ppolicy_ext_*.so
echo ""
echo "验证文件架构:"
file "$OUTPUT_DIR"/ppolicy_ext_*.so
