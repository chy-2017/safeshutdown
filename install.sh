#!/bin/sh
# safeshutdown 一键安装脚本
# 用法: sudo ./install.sh
set -e

BINDIR="${DESTDIR:-}/usr/local/sbin"
CONFDIR="${DESTDIR:-}/etc"
SYSDDIR="${DESTDIR:-}/etc/systemd/system"

echo "=== safeshutdown 安装脚本 ==="

# 检查 root
if [ "$(id -u)" -ne 0 ]; then
    echo "错误：需要 root 权限！请使用 sudo ./install.sh"
    exit 1
fi

# 检查二进制
if [ ! -f safeshutdown ]; then
    echo "错误：未找到 safeshutdown 二进制文件"
    echo "请先编译: gcc -O2 -Wall -Wextra -std=c11 -o safeshutdown safeshutdown.c -lpthread"
    exit 1
fi

echo "安装二进制到 $BINDIR/safeshutdown"
install -d "$BINDIR"
install -m 755 safeshutdown "$BINDIR/safeshutdown"

echo "安装配置文件到 $CONFDIR/safeshutdown.conf"
if [ -f "$CONFDIR/safeshutdown.conf" ]; then
    echo "  配置文件已存在，备份为 safeshutdown.conf.bak"
    cp "$CONFDIR/safeshutdown.conf" "$CONFDIR/safeshutdown.conf.bak"
fi
install -m 644 safeshutdown.conf "$CONFDIR/safeshutdown.conf"

echo "安装 systemd 服务到 $SYSDDIR/safeshutdown.service"
install -d "$SYSDDIR"
install -m 644 safeshutdown.service "$SYSDDIR/safeshutdown.service"

echo ""
echo "=== 安装完成 ==="
echo ""
echo "启动服务: sudo systemctl enable --now safeshutdown"
echo "查看日志: journalctl -u safeshutdown -f"
echo "测试模式: sudo safeshutdown -d -n"
echo ""

# 询问是否启动
printf "是否现在启动服务？ [y/N] "
read -r answer
case "$answer" in
    y|Y|yes|Yes)
        systemctl daemon-reload
        systemctl enable --now safeshutdown
        echo "服务已启动！"
        journalctl -u safeshutdown -n 5 --no-pager
        ;;
    *)
        echo "已跳过。您可以稍后手动启动。"
        ;;
esac
