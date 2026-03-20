#!/bin/bash
# 使用 Docker + Ubuntu 构建 ppolicy-extensions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ppolicy-extensions Docker Build ==="
echo "使用 Ubuntu:latest + OpenLDAP 开发环境"

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo "错误: Docker 未安装"
    exit 1
fi

# 检查 docker-compose 是否安装
if ! command -v docker-compose &> /dev/null; then
    echo "警告: docker-compose 未安装，使用 docker build"
    echo ""
    echo "构建命令:"
    echo "  docker build -t ppolicy-extensions-builder ."
    echo "  docker run --rm -v \$(pwd):/workspace/ppolicy-extensions ppolicy-extensions-builder make all"
    exit 1
fi

# 使用 docker-compose 构建
echo ""
echo "1. 启动构建环境..."
docker-compose up -d --build

echo ""
echo "2. 编译项目..."
docker-compose exec builder make clean all

echo ""
echo "3. 复制编译产物..."
mkdir -p lib
docker-compose exec builder make lib/ppolicy_ext.so
cp -n lib/* lib/ 2>/dev/null || true

echo ""
echo "=== 构建完成 ==="
echo "编译产物位于: lib/ppolicy_ext.so"
echo ""
echo "使用以下命令进入构建环境:"
echo "  ./build-docker.sh shell"
