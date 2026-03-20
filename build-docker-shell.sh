#!/bin/bash
# 进入 Docker 构建环境 shell

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v docker-compose &> /dev/null; then
    echo "错误: docker-compose 未安装"
    exit 1
fi

echo "进入 ppolicy-extensions 构建环境..."
docker-compose exec builder /bin/bash
