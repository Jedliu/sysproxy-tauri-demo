#!/bin/bash

# mihomo 二进制下载脚本
# 从 MetaCubeX/mihomo releases 下载最新版本

set -e

SIDECAR_DIR="$(cd "$(dirname "$0")" && pwd)/src-tauri/sidecar"
MIHOMO_VERSION="v1.18.10"  # 最新稳定版本
BASE_URL="https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}"

echo "正在下载 mihomo 二进制文件..."
echo "版本: ${MIHOMO_VERSION}"
echo "目标目录: ${SIDECAR_DIR}"
echo ""

# 创建临时目录
TMP_DIR=$(mktemp -d)
trap "rm -rf ${TMP_DIR}" EXIT

# 检测操作系统
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        FILE="mihomo-darwin-amd64-compatible-${MIHOMO_VERSION}.gz"
        TARGET="verge-mihomo-x86_64-apple-darwin"
    elif [[ "$ARCH" == "arm64" ]]; then
        FILE="mihomo-darwin-arm64-${MIHOMO_VERSION}.gz"
        TARGET="verge-mihomo-aarch64-apple-darwin"
    else
        echo "错误: 不支持的 macOS 架构: $ARCH"
        exit 1
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    FILE="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz"
    TARGET="verge-mihomo-x86_64-unknown-linux-gnu"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    # Windows (Git Bash)
    FILE="mihomo-windows-amd64-compatible-${MIHOMO_VERSION}.zip"
    TARGET="verge-mihomo-x86_64-pc-windows-msvc.exe"
else
    echo "错误: 不支持的操作系统: $OSTYPE"
    exit 1
fi

echo "下载文件: $FILE"
echo "目标文件名: $TARGET"
echo ""

# 下载文件
DOWNLOAD_URL="${BASE_URL}/${FILE}"
echo "从 $DOWNLOAD_URL 下载..."

if command -v curl &> /dev/null; then
    curl -L -o "${TMP_DIR}/${FILE}" "${DOWNLOAD_URL}"
elif command -v wget &> /dev/null; then
    wget -O "${TMP_DIR}/${FILE}" "${DOWNLOAD_URL}"
else
    echo "错误: 需要 curl 或 wget 来下载文件"
    exit 1
fi

echo "✓ 下载完成"
echo ""

# 解压文件
echo "正在解压..."
cd "${TMP_DIR}"

if [[ "$FILE" == *.gz ]]; then
    gunzip "${FILE}"
    EXTRACTED_FILE="${FILE%.gz}"
elif [[ "$FILE" == *.zip ]]; then
    unzip -q "${FILE}"
    EXTRACTED_FILE="mihomo-windows-amd64-compatible.exe"
fi

echo "✓ 解压完成"
echo ""

# 移动到 sidecar 目录
echo "正在安装到 sidecar 目录..."
mkdir -p "${SIDECAR_DIR}"
mv "${EXTRACTED_FILE}" "${SIDECAR_DIR}/${TARGET}"
chmod +x "${SIDECAR_DIR}/${TARGET}"

echo "✓ 安装完成"
echo ""
echo "mihomo 二进制已安装到: ${SIDECAR_DIR}/${TARGET}"
echo ""

# 验证
if [[ -f "${SIDECAR_DIR}/${TARGET}" ]]; then
    FILE_SIZE=$(du -h "${SIDECAR_DIR}/${TARGET}" | cut -f1)
    echo "文件大小: ${FILE_SIZE}"
    echo "✓ 验证成功"
    echo ""
    echo "您现在可以运行 'pnpm dev' 或 'pnpm build' 来构建应用程序。"
else
    echo "错误: 安装验证失败"
    exit 1
fi
