# safeshutdown — 系统安全监护程序

当系统发生内存溢出(OOM)、CPU 满载、IO 卡死时自动安全关机，防止数据丢失。

## 快速开始

### 方式一：从 Release 下载二进制（推荐）

从 GitHub Releases 页面下载对应架构的预编译二进制。

### 方式二：自行编译

```bash
gcc -O2 -Wall -Wextra -std=c11 -o safeshutdown safeshutdown.c -lpthread
sudo cp safeshutdown /usr/local/sbin/
```

### 安装

```bash
sudo cp safeshutdown.conf /etc/safeshutdown.conf    # 可选：自定义配置
sudo cp safeshutdown.service /etc/systemd/system/
sudo systemctl enable --now safeshutdown
```

## 工作原理

### 监控维度
| 维度 | 数据源 | 默认阈值 |
|------|--------|---------|
| 可用内存 | `/proc/meminfo` | < 4% → CRITICAL |
| 内存压力 | `/proc/pressure/memory` PSI avg10 > 70% → CRITICAL |
| CPU 负载 | `/proc/loadavg` | 负载/核心 > 6 → CRITICAL |
| OOM 事件 | `/proc/vmstat` oom_kill | ≥ 1 次 → EMERGENCY |
| IO 卡死 | `/proc/pressure/io` full avg10 > 90% → CRITICAL |

### 告警升级机制
```
OK → WARNING (日志) → CRITICAL (sync) → EMERGENCY (关机) → PANIC (SysRq)
```

### 双进程监护
```
主进程 ─── 心跳文件 ─── 看门狗子进程
  │                         │
  ├─ 健康检查                ├─ 检查心跳超时
  ├─ 喂 /dev/watchdog       ├─ 独立内存检查
  └─ 执行关机                └─ 主进程卡死时强制关机
```

### 关机序列
1. `sync()` 同步文件系统
2. `systemctl poweroff` 正常关机
3. `systemctl poweroff --force` 强制关机
4. **Magic SysRq REISUB** 终极重启
5. *(硬件看门狗超时触发硬件复位)*

## 自身资源占用
- **内存**: < 2MB RSS（看门狗子进程 < 8MB 地址空间上限）
- **CPU**: < 0.1%（每 2 秒唤醒一次，其余时间睡眠）
- **磁盘**: 仅心跳文件写入
- **无动态内存分配**：所有缓冲区在栈上分配

## 配置

编辑 `/etc/safeshutdown.conf`：

```
# 检查间隔（毫秒）
check_interval_ms = 2000

# 可用内存 ≤ 此百分比触发 CRITICAL
mem_critical_pct = 4

# CPU 负载/核心数 > 此值触发 CRITICAL
cpu_load_critical = 6

# 测试模式：仅日志不关机
dry_run = false
```

## 测试

```bash
# dry-run 模式（不会实际关机）
sudo ./safeshutdown -d -n

# 查看日志
journalctl -u safeshutdown -f
```

## 架构支持

通过 GitHub Actions 自动编译：
- `amd64` (glibc / musl)
- `aarch64/arm64` (glibc / musl)
- `i686` (glibc)

## License

MIT
