/*
 * safeshutdown.c — 系统安全监护程序
 *
 * 功能：监控系统内存、CPU、响应性，在异常时安全关机
 * 设计要点：
 *   - 自身占用极低 (< 2MB RSS, < 0.1% CPU)
 *   - 双进程监护（主进程 + 看门狗子进程）
 *   - 四层告警升级机制
 *   - 优先保护数据不丢失
 *
 * 编译: gcc -O2 -Wall -Wextra -std=c11 -o safeshutdown safeshutdown.c
 * 运行: sudo ./safeshutdown [-d] [-n] [-c 配置文件]
 *
 * 配置文件: /etc/safeshutdown.conf (可选)
 *
 * 架构：
 *   1. 守护化（不关闭已打开的文件描述符）
 *   2. 创建心跳文件
 *   3. fork 看门狗子进程（独立监控主进程心跳）
 *   4. 启动看门狗 feeder 线程（喂 /dev/watchdog）
 *   5. 主循环：健康检查 → 告警升级 → 关机执行
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <limits.h>
#include <pthread.h>
#include <linux/watchdog.h>

/* ================================================================
 * 配置（硬编码默认值，可由配置文件覆盖）
 * ================================================================ */
typedef struct {
    int  check_interval_ms;        /* 检查间隔（毫秒） */
    int  watchdog_timeout_sec;     /* 看门狗超时（秒，对软硬狗都有效） */
    int  heartbeat_timeout_sec;    /* 心跳超时（秒，子进程检测主进程是否卡死） */
    int  grace_period_sec;         /* 关机的宽限期（秒） */

    /* 内存阈值 */
    int  mem_critical_pct;         /* 可用内存比例低于此 → CRITICAL (%) */
    int  mem_warning_pct;          /* 可用内存比例低于此 → WARNING (%) */

    /* 内存压力（PSI）阈值 */
    int  psi_mem_critical;         /* 内存 PSI avg10 > 此值 → CRITICAL */
    int  psi_mem_warning;          /* 内存 PSI avg10 > 此值 → WARNING */

    /* CPU 阈值 */
    int  cpu_load_critical;        /* load_avg / cpu_count > 此值 → CRITICAL */
    int  cpu_load_warning;         /* load_avg / cpu_count > 此值 → WARNING */

    /* OOM */
    int  oom_kill_threshold;       /* 检查间隔内 OOM kill 计数增量 > 此值 → CRITICAL */

    /* IO 压力 */
    int  psi_io_critical;          /* IO PSI full avg10 > 此值 → CRITICAL */

    bool dry_run;                  /* 仅日志，不实际关机 */
    bool use_sysrq;                /* 允许使用 Magic SysRq */
} Config;

static const Config DEFAULT_CONFIG = {
    .check_interval_ms      = 2000,
    .watchdog_timeout_sec   = 20,
    .heartbeat_timeout_sec  = 10,
    .grace_period_sec       = 15,
    .mem_critical_pct       = 8,
    .mem_warning_pct        = 15,
    .psi_mem_critical       = 50,
    .psi_mem_warning        = 30,
    .cpu_load_critical      = 5,
    .cpu_load_warning       = 3,
    .oom_kill_threshold     = 1,
    .psi_io_critical        = 80,
    .dry_run                = false,
    .use_sysrq              = true,
};

static Config cfg;

/* ================================================================
 * 全局状态
 * ================================================================ */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_escalation_level = 0; /* 0=OK, 1=WARN, 2=CRIT, 3=EMERG, 4=PANIC */
static pid_t g_watchdog_pid = 0;      /* 看门狗子进程 PID */
static int   g_heartbeat_fd = -1;     /* 心跳文件描述符 */
static int   g_watchdog_fd  = -1;     /* /dev/watchdog 文件描述符 */
static char  g_heartbeat_path[256];   /* 心跳文件路径 */
static int   g_oom_last = 0;          /* 上次 OOM kill 计数 */
static int   g_cpu_count = 0;         /* CPU 核心数 */
/* 告警持续计数：连续 N 周期未恢复则自动升级 */
static int   g_escalation_persist = 0;

/* 锁：escalation_level 写保护 */
static pthread_mutex_t g_level_lock = PTHREAD_MUTEX_INITIALIZER;

/* ================================================================
 * 实用工具函数
 * ================================================================ */

/* 获取时间戳（毫秒） */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* 安全地读一个 /proc 文件到固定缓冲区，返回读取的字节数，失败返回 -1 */
static int read_proc_file(const char *path, char *buf, size_t size)
{
    int fd;
    ssize_t n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    n = read(fd, buf, size - 1);
    close(fd);

    if (n <= 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

/* syslog + dry-run 时也输出到 stderr */
static void log_msg(int priority, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);

    if (cfg.dry_run) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }
}

/* ================================================================
 * 告警级别管理
 * ================================================================ */
static const char *level_name(int level)
{
    switch (level) {
        case 0: return "OK";
        case 1: return "WARNING";
        case 2: return "CRITICAL";
        case 3: return "EMERGENCY";
        case 4: return "PANIC";
        default: return "UNKNOWN";
    }
}

static void set_level(int level)
{
    pthread_mutex_lock(&g_level_lock);
    if (level > g_escalation_level) {
        g_escalation_level = level;
        log_msg(LOG_CRIT, "告警级别升级到 %s", level_name(level));
    }
    pthread_mutex_unlock(&g_level_lock);
}

static int get_level(void)
{
    int l;
    pthread_mutex_lock(&g_level_lock);
    l = g_escalation_level;
    pthread_mutex_unlock(&g_level_lock);
    return l;
}

static void reset_level(void)
{
    pthread_mutex_lock(&g_level_lock);
    g_escalation_level = 0;
    pthread_mutex_unlock(&g_level_lock);
}

/* ================================================================
 * 系统信息采集（全部零分配，栈上操作）
 * ================================================================ */

/* 读取 CPU 个数 */
static int get_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
}

/* 内存信息：返回可用内存百分比 (0-100) */
static int get_mem_available_pct(void)
{
    char buf[2048];
    long mem_total = 0, mem_avail = 0;

    if (read_proc_file("/proc/meminfo", buf, sizeof(buf)) < 0)
        return -1;

    /* 逐行解析 */
    char *line = buf;
    char *nl;
    while ((nl = strchr(line, '\n')) != NULL) {
        *nl = '\0';
        if (strncmp(line, "MemTotal:", 9) == 0)
            mem_total = atol(line + 9);
        else if (strncmp(line, "MemAvailable:", 13) == 0)
            mem_avail = atol(line + 13);
        line = nl + 1;
    }
    if (mem_total <= 0 || mem_avail <= 0)
        return -1;

    return (int)(mem_avail * 100LL / mem_total);
}

/* PSI 内存压力：返回 avg10 值（浮点*10取整），失败返回 -1 */
static int get_psi_mem_avg10(void)
{
    char buf[512];
    if (read_proc_file("/proc/pressure/memory", buf, sizeof(buf)) < 0)
        return -1;

    /* 格式: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0" */
    char *p = strstr(buf, "avg10=");
    if (!p) return -1;
    p += 6;
    double val = strtod(p, NULL);
    return (int)(val * 10);
}

/* IO 压力：返回 full avg10 值 * 10，失败返回 -1 */
static int get_psi_io_full_avg10(void)
{
    char buf[512];
    if (read_proc_file("/proc/pressure/io", buf, sizeof(buf)) < 0)
        return -1;

    char *full = strstr(buf, "full avg10=");
    if (!full) return -1;
    full += 11;
    double val = strtod(full, NULL);
    return (int)(val * 10);
}

/* 获取当前 OOM kill 计数 */
static int get_oom_kills(void)
{
    char buf[4096];
    if (read_proc_file("/proc/vmstat", buf, sizeof(buf)) < 0)
        return -1;

    char *p = strstr(buf, "oom_kill ");
    if (!p) return -1;
    p += 9;
    return (int)strtol(p, NULL, 10);
}

/* CPU 负载：返回 loadavg1 * 10 */
static int get_load_avg_x10(void)
{
    char buf[128];
    if (read_proc_file("/proc/loadavg", buf, sizeof(buf)) < 0)
        return -1;
    double val = strtod(buf, NULL);
    return (int)(val * 10);
}

/* ================================================================
 * 执行关机
 * ================================================================ */

/* 同步文件系统 */
static void sync_filesystems(void)
{
    log_msg(LOG_CRIT, "[关机] 正在同步文件系统...");
    sync();
    sleep(2);
    sync();
}

/* 尝试正常关机 */
static void try_graceful_shutdown(void)
{
    log_msg(LOG_CRIT, "[关机] 尝试正常关机...");
    if (cfg.dry_run) {
        log_msg(LOG_CRIT, "[DRY RUN] 跳过 systemctl poweroff");
        return;
    }
    int ret = system("systemctl poweroff 2>/dev/null &");
    if (ret != 0) {
        log_msg(LOG_ERR, "[关机] systemctl poweroff 返回 %d", ret);
    }
}

/* 尝试强制关机 */
static void try_force_shutdown(void)
{
    log_msg(LOG_CRIT, "[关机] 尝试强制关机...");
    if (cfg.dry_run) {
        log_msg(LOG_CRIT, "[DRY RUN] 跳过 systemctl poweroff --force");
        return;
    }
    int ret = system("systemctl poweroff --force 2>/dev/null &");
    if (ret != 0) {
        log_msg(LOG_ERR, "[关机] systemctl poweroff --force 返回 %d", ret);
    }
}

/* 最后手段：Magic SysRq REISUB 序列 */
static void try_sysrq(void)
{
    if (!cfg.use_sysrq) return;

    log_msg(LOG_CRIT, "[关机] 发出 Magic SysRq 紧急重启...");

    if (cfg.dry_run) {
        log_msg(LOG_CRIT, "[DRY RUN] 跳过 SysRq");
        return;
    }

    /* 先确保 sysrq 已启用 */
    int fd = open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        log_msg(LOG_ERR, "[关机] 无法打开 /proc/sysrq-trigger (errno=%d)", errno);

        /* 尝试启用 */
        int sysrq_fd = open("/proc/sys/kernel/sysrq", O_WRONLY | O_CLOEXEC);
        if (sysrq_fd >= 0) {
            write(sysrq_fd, "1\n", 2);
            close(sysrq_fd);
            sleep(1);
            fd = open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC);
        }
    }

    if (fd < 0) {
        log_msg(LOG_ERR, "[关机] 无法使用 SysRq，跳过");
        return;
    }

    /* REISUB 序列：先安全停止一切，再重启 */
    write(fd, "r", 1); sleep(1); /* 切换键盘为 raw 模式 */
    write(fd, "e", 1); sleep(1); /* 给所有进程发送 SIGTERM */
    write(fd, "i", 1); sleep(1); /* 给所有进程发送 SIGKILL */
    write(fd, "s", 1); sleep(2); /* 同步文件系统 */
    write(fd, "u", 1); sleep(1); /* 重新挂载为只读 */
    write(fd, "b", 1);           /* 立即重启 */
    close(fd);
}

/* 执行告警升级后的动作 */
static void execute_escalation(int level)
{
    switch (level) {
    case 1: /* WARNING：仅记录 */
        log_msg(LOG_WARNING, "[WARNING] 系统负载偏高，持续监控中");
        break;

    case 2: /* CRITICAL：开始准备 */
        log_msg(LOG_CRIT, "[CRITICAL] 系统状态严重！准备关机...");
        sync_filesystems();
        /* 给一次恢复机会，下个周期如果仍然持续则升级 */
        break;

    case 3: /* EMERGENCY：开始关机 */
        log_msg(LOG_CRIT, "[EMERGENCY] 开始安全关机！");

        /* 先同步 */
        sync_filesystems();

        /* 等待 grace_period 秒让同步完成 */
        log_msg(LOG_CRIT, "[关机] 等待 %d 秒完成同步...", cfg.grace_period_sec);
        sleep(cfg.grace_period_sec);
        sync();

        /* 尝试正常关机 */
        try_graceful_shutdown();

        /* 等待几秒看是否成功 */
        sleep(5);

        /* 如果还没关机，尝试强制 */
        if (get_level() >= 3) {
            try_force_shutdown();
        }
        break;

    case 4: /* PANIC：终极手段 */
        log_msg(LOG_CRIT, "[PANIC] 正常关机失败！使用最后手段...");
        sync_filesystems();
        sleep(2);

        try_force_shutdown();
        sleep(3);

        try_sysrq();
        break;
    }
}

/* ================================================================
 * 主监控循环（健康检查）
 * ================================================================ */

static void health_check(void)
{
    int mem_pct, psi_mem, psi_io, load_x10, oom_now, oom_delta;
    double load_per_cpu;

    /* ---- OOM kill 检测（最优先：系统真死了） ---- */
    oom_now = get_oom_kills();
    if (oom_now >= 0) {
        oom_delta = oom_now - g_oom_last;
        g_oom_last = oom_now;
        if (oom_delta >= cfg.oom_kill_threshold) {
            log_msg(LOG_CRIT, "检测到 OOM kill（本轮 %d 次，累计 %d 次）！",
                    oom_delta, oom_now);
            set_level(3); /* 直接 EMERGENCY */
            return;
        }
    }

    /* ---- PSI 内存压力（比内存百分比更准确） ---- */
    psi_mem = get_psi_mem_avg10();
    mem_pct = get_mem_available_pct();

    if (psi_mem >= 0 && mem_pct >= 0 &&
        psi_mem >= cfg.psi_mem_critical * 10 &&
        mem_pct < cfg.mem_critical_pct) {
        /* 内存低 + 压力大 → 系统真正在 thrashing */
        log_msg(LOG_CRIT, "内存压力 PSI avg10=%d.%d，可用仅 %d%%",
                psi_mem / 10, psi_mem % 10, mem_pct);
        set_level(2);
        return;
    }

    if (psi_mem >= 0 && psi_mem >= cfg.psi_mem_critical * 10) {
        log_msg(LOG_CRIT, "内存压力 PSI avg10=%d.%d（阈值 %d%%）",
                psi_mem / 10, psi_mem % 10, cfg.psi_mem_critical);
        set_level(2);
        return;
    }

    if (psi_mem >= 0 && psi_mem >= cfg.psi_mem_warning * 10) {
        log_msg(LOG_WARNING, "内存压力 PSI avg10=%d.%d（警告阈值 %d%%）",
                psi_mem / 10, psi_mem % 10, cfg.psi_mem_warning);
        set_level(1);
    }

    /* ---- IO 压力（卡死检测） ---- */
    psi_io = get_psi_io_full_avg10();
    if (psi_io >= 0 && psi_io >= cfg.psi_io_critical * 10) {
        log_msg(LOG_CRIT, "IO 压力 full avg10=%d.%d（阈值 %d%%）",
                psi_io / 10, psi_io % 10, cfg.psi_io_critical);
        set_level(2);
        return;
    }

    /* ---- CPU 负载（仅告警，不直接触发关机） ---- */
    load_x10 = get_load_avg_x10();
    if (load_x10 >= 0) {
        load_per_cpu = (double)load_x10 / 10.0 / (double)g_cpu_count;
        if (load_per_cpu >= (double)cfg.cpu_load_critical) {
            log_msg(LOG_WARNING, "CPU 负载 %.1f（核心数 %d, 严重）",
                    load_per_cpu, g_cpu_count);
            set_level(1);
        } else if (load_per_cpu >= (double)cfg.cpu_load_warning) {
            log_msg(LOG_WARNING, "CPU 负载 %.1f（核心数 %d, 偏高）",
                    load_per_cpu, g_cpu_count);
            set_level(1);
        }
    }

    /* ---- 纯低内存（PSI 正常→只是缓存占用，不关机） ---- */
    if (mem_pct >= 0 && mem_pct < cfg.mem_warning_pct) {
        log_msg(LOG_WARNING, "可用内存剩 %d%%（PSI 正常，仅提醒）", mem_pct);
        set_level(1);
    }

    /* ---- 一切正常，降级 ---- */
    if (get_level() == 1) {
        log_msg(LOG_INFO, "系统恢复正常");
    }
    reset_level();
}

/* ================================================================
 * 更新心跳（主进程通知看门狗子进程自己还活着）
 * ================================================================ */

static void update_heartbeat(void)
{
    if (g_heartbeat_fd < 0) return;

    char buf[32];
    long long t = now_ms();
    int n = snprintf(buf, sizeof(buf), "%lld\n", t);

    lseek(g_heartbeat_fd, 0, SEEK_SET);
    ftruncate(g_heartbeat_fd, 0);
    write(g_heartbeat_fd, buf, (size_t)n);
    fsync(g_heartbeat_fd);
}

/* ================================================================
 * 看门狗子进程：独立于主进程的心跳监控
 *
 * 功能：
 *   - 读取主进程的心跳文件，检测主进程是否卡死
 *   - 独立做简单内存检查作为双重保障
 *   - 主进程挂掉时执行紧急关机
 *
 * 注意：子进程在 fork 后独立运行，拥有 cfg 的独立拷贝。
 *       g_running 也是独立拷贝（写时复制）。
 * ================================================================ */
static void watchdog_child_loop(void)
{
    /* 重置信号处理器为默认行为，让父进程能 kill 掉子进程 */
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT,  SIG_DFL);
    signal(SIGQUIT, SIG_DFL);

    /* 关闭 stdin，最小化资源 */
    close(0);

    /* 限制地址空间（间接限制 RSS） */
    {
        struct rlimit rlim;
        rlim.rlim_cur = 8 * 1024 * 1024;  /* 8MB 地址空间上限 */
        rlim.rlim_max = 8 * 1024 * 1024;
        setrlimit(RLIMIT_AS, &rlim);
    }

    /* 尝试打开心跳文件（主进程可能尚未创建，等待片刻） */
    int heartbeat_fd = -1;
    for (int tries = 0; tries < 5 && heartbeat_fd < 0; tries++) {
        heartbeat_fd = open(g_heartbeat_path, O_RDONLY | O_CLOEXEC);
        if (heartbeat_fd < 0 && tries < 4) sleep(1);
    }

    if (heartbeat_fd < 0) {
        syslog(LOG_CRIT, "[看门狗] 无法打开心跳文件 %s，执行紧急关机！", g_heartbeat_path);
        sync();
        system("systemctl poweroff --force &");
        _exit(1);
    }

    /* 子进程自己的连续失败计数器 */
    int consecutive_failures = 0;
    const int max_failures = 3;

    for (;;) {
        /* 定期检查：每 2 秒一次 */
        sleep(2);

        char buf[32];
        long long t, now;

        /* 读取心跳时间戳 */
        memset(buf, 0, sizeof(buf));
        lseek(heartbeat_fd, 0, SEEK_SET);
        ssize_t n = read(heartbeat_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            t = strtoll(buf, NULL, 10);
            now = now_ms();

            if (now - t > (long long)cfg.heartbeat_timeout_sec * 1000LL) {
                consecutive_failures++;
                if (consecutive_failures >= max_failures) {
                    syslog(LOG_CRIT, "[看门狗] 主进程心跳超时 %lld 秒！执行紧急关机！",
                           (now - t) / 1000LL);
                    sync();
                    system("systemctl poweroff --force &");
                    sleep(5);
                    /* 尝试 SysRq */
                    int fd = open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC);
                    if (fd >= 0) {
                        write(fd, "s", 1); sleep(1);
                        write(fd, "u", 1); sleep(1);
                        write(fd, "b", 1);
                        close(fd);
                    }
                    _exit(2);
                }
            } else {
                /* 心跳正常，递减失败计数（但不低于 0） */
                if (consecutive_failures > 0)
                    consecutive_failures--;
            }
        }

        /* 子进程也做简单的独立内存检查作为双重保障 */
        {
            char mbuf[1024];
            long mem_avail = -1, mem_total = -1;
            if (read_proc_file("/proc/meminfo", mbuf, sizeof(mbuf)) >= 0) {
                char *p = strstr(mbuf, "MemAvailable:");
                if (p) mem_avail = atol(p + 13);
                p = strstr(mbuf, "MemTotal:");
                if (p) mem_total = atol(p + 9);
            }
            if (mem_total > 0 && mem_avail >= 0) {
                int pct = (int)(mem_avail * 100LL / mem_total);
                if (pct < cfg.mem_critical_pct) {
                    consecutive_failures++;
                    if (consecutive_failures >= max_failures) {
                        syslog(LOG_CRIT, "[看门狗] 可用内存仅 %d%%，执行紧急关机！", pct);
                        sync();
                        system("systemctl poweroff --force &");
                        _exit(3);
                    }
                } else {
                    if (consecutive_failures > 0)
                        consecutive_failures--;
                }
            }
        }
    }

    /* 不会到达这里 */
    close(heartbeat_fd);
}

/* ================================================================
 * 看门狗硬件/软件 feeding 线程
 *
 * 如果有 /dev/watchdog，主进程定期喂狗。
 * 当系统正常时 (level < 3) 持续喂狗；
 * 当系统异常时 (level >= 3) 停止喂狗，让硬件触发复位。
 * ================================================================ */

static void *watchdog_feeder_thread(void *arg)
{
    (void)arg;

    /* 尝试打开硬件/软件看门狗 */
    int wd_fd = open("/dev/watchdog", O_WRONLY | O_CLOEXEC);
    if (wd_fd < 0) {
        /* 尝试加载 softdog 模块 */
        system("modprobe softdog 2>/dev/null");
        sleep(1);
        wd_fd = open("/dev/watchdog", O_WRONLY | O_CLOEXEC);
    }

    g_watchdog_fd = wd_fd;

    if (wd_fd >= 0) {
        /* 设置看门狗超时 */
        int timeout = cfg.watchdog_timeout_sec;
        if (ioctl(wd_fd, WDIOC_SETTIMEOUT, &timeout) < 0) {
            syslog(LOG_WARNING, "[看门狗] 设置超时失败，使用默认值");
        }
        syslog(LOG_INFO, "[看门狗] 硬件看门狗已启用，超时 %d 秒", cfg.watchdog_timeout_sec);
    } else {
        syslog(LOG_INFO, "[看门狗] 无 /dev/watchdog，使用进程心跳作为唯一监护");
    }

    /* 喂狗间隔：watchdog_timeout_sec / 2，确保在超时前喂足 */
    int pet_interval = cfg.watchdog_timeout_sec / 2;
    if (pet_interval < 1) pet_interval = 1;

    while (1) {
        int level = get_level();

        if (g_watchdog_fd >= 0) {
            if (level < 3) {
                /* 系统正常，喂狗 */
                write(g_watchdog_fd, "", 1);
            } else {
                /* level >= 3：关机流程已启动，停止喂狗
                 * 让硬件看门狗超时作为最后的安全网 */
                syslog(LOG_CRIT, "[看门狗] 系统异常，停止喂狗");
                /* 睡眠足够长让看门狗超时 */
                sleep(cfg.watchdog_timeout_sec + 10);
            }
        }

        /* 按间隔睡眠 */
        for (int i = 0; i < pet_interval; i++) {
            sleep(1);
            if (get_level() >= 3 && g_watchdog_fd >= 0) {
                /* 如果已进入关机流程，不再继续喂 */
                sleep(cfg.watchdog_timeout_sec + 10);
                break;
            }
        }
    }

    /* 不会到达这里 */
    return NULL;
}

/* ================================================================
 * 信号处理
 *
 * 注意：信号处理器中只做 volatile 变量标记，
 *       不调用任何非 async-signal-safe 的函数。
 * ================================================================ */

static void handle_signal(int sig)
{
    switch (sig) {
    case SIGTERM:
    case SIGINT:
    case SIGQUIT:
        g_running = 0;
        break;
    default:
        break;
    }
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sa.sa_flags   = SA_RESTART;
    sigfillset(&sa.sa_mask);

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    /* 忽略子进程退出信号，避免僵尸 */
    signal(SIGCHLD, SIG_IGN);
}

/* ================================================================
 * 配置文件解析
 * ================================================================ */

static int parse_config_line(const char *line)
{
    char key[64], val[256];

    if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
        return 0;

    if (sscanf(line, "%63s = %255s", key, val) < 2)
        return 0;

    /* 去掉 value 中的引号 */
    char *p = val;
    if (*p == '"' || *p == '\'') {
        size_t len = strlen(p);
        if (len > 2 && p[len-1] == *p) {
            p[len-1] = '\0';
            p++;
        }
    }

#define SET_INT(field) do { \
    long v = strtol(p, NULL, 10); \
    cfg.field = (int)v; \
} while(0)

#define SET_BOOL(field) do { \
    cfg.field = (strcmp(p, "true") == 0 || strcmp(p, "1") == 0 || strcmp(p, "yes") == 0); \
} while(0)

    if      (strcmp(key, "check_interval_ms")    == 0) SET_INT(check_interval_ms);
    else if (strcmp(key, "watchdog_timeout_sec")  == 0) SET_INT(watchdog_timeout_sec);
    else if (strcmp(key, "heartbeat_timeout_sec") == 0) SET_INT(heartbeat_timeout_sec);
    else if (strcmp(key, "grace_period_sec")      == 0) SET_INT(grace_period_sec);
    else if (strcmp(key, "mem_critical_pct")      == 0) SET_INT(mem_critical_pct);
    else if (strcmp(key, "mem_warning_pct")       == 0) SET_INT(mem_warning_pct);
    else if (strcmp(key, "psi_mem_critical")      == 0) SET_INT(psi_mem_critical);
    else if (strcmp(key, "psi_mem_warning")       == 0) SET_INT(psi_mem_warning);
    else if (strcmp(key, "cpu_load_critical")     == 0) SET_INT(cpu_load_critical);
    else if (strcmp(key, "cpu_load_warning")      == 0) SET_INT(cpu_load_warning);
    else if (strcmp(key, "oom_kill_threshold")    == 0) SET_INT(oom_kill_threshold);
    else if (strcmp(key, "psi_io_critical")       == 0) SET_INT(psi_io_critical);
    else if (strcmp(key, "dry_run")               == 0) SET_BOOL(dry_run);
    else if (strcmp(key, "use_sysrq")             == 0) SET_BOOL(use_sysrq);

    return 0;
}

static int load_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        parse_config_line(line);
    }
    fclose(fp);
    return 0;
}

/* ================================================================
 * 打印使用说明
 * ================================================================ */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "用法: %s [选项]\n"
        "\n"
        "系统安全监护程序 — 在内存溢出/CPU满载/系统卡死时安全关机\n"
        "\n"
        "选项:\n"
        "  -c <文件>   配置文件路径 (默认: /etc/safeshutdown.conf)\n"
        "  -d          调试/前台模式 (不守护化)\n"
        "  -n          dry-run 模式 (仅日志, 不关机)\n"
        "  -h          显示此帮助\n"
        "\n"
        "配置文件格式:\n"
        "  check_interval_ms    = 2000    # 检查间隔(毫秒)\n"
        "  mem_critical_pct     = 4       # 可用内存 ≤ 此 %% 触发临界\n"
        "  cpu_load_critical    = 6       # 负载/核心数 > 此值触发临界\n"
        "  dry_run              = false   # 仅记录不关机\n"
        "\n",
        prog ? prog : "safeshutdown");
}

/* ================================================================
 * 手动守护化（比 daemon() 更可控）
 *
 * 我们不使用 daemon() 因为它会关闭所有文件描述符，
 * 而我们希望保留心跳文件的 fd。
 *
 * 返回 0 表示成功（在子进程中），-1 表示失败。
 * 父进程会 exit(0)。
 * ================================================================ */
static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        log_msg(LOG_ERR, "daemonize fork 失败: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        /* 父进程：退出 */
        _exit(0);
    }

    /* 子进程：成为会话组长 */
    if (setsid() < 0) {
        return -1;
    }

    /* 第二次 fork，确保不会重新获取控制终端 */
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);

    /* 设置工作目录 */
    chdir("/");

    /* 重置 umask */
    umask(022);

    return 0;
}

/* ================================================================
 * main
 * ================================================================ */

int main(int argc, char *argv[])
{
    const char *config_path = "/etc/safeshutdown.conf";
    bool daemonize_mode = true;
    int opt;

    /* 初始化配置 */
    cfg = DEFAULT_CONFIG;

    /* 解析命令行 */
    while ((opt = getopt(argc, argv, "c:dnh")) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'd': daemonize_mode = false; break;
        case 'n': cfg.dry_run = true; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    /* 以 root 运行检查 */
    if (geteuid() != 0 && !cfg.dry_run) {
        fprintf(stderr, "错误：需要 root 权限运行！请使用 sudo。\n");
        return 1;
    }

    /* 加载配置 */
    load_config(config_path);

    /* CPU 核心数 */
    g_cpu_count = get_cpu_count();

    /* 打开日志（守护化后会重开） */
    openlog("safeshutdown", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);

    log_msg(LOG_INFO, "===== safeshutdown v1.0 启动 =====");
    log_msg(LOG_INFO, "CPU: %d 核心, 检查间隔: %dms",
            g_cpu_count, cfg.check_interval_ms);
    log_msg(LOG_INFO, "阈值: 内存 <%d%%, CPU 负载 >%d/核心, OOM ≥%d",
            cfg.mem_critical_pct, cfg.cpu_load_critical, cfg.oom_kill_threshold);
    if (cfg.dry_run) {
        log_msg(LOG_WARNING, "DRY RUN 模式：不会实际关机");
    }

    /* 设置信号处理 */
    setup_signals();

    /* ============================================================
     * 第1步：守护化（先守护化，再 fork 子进程）
     * ============================================================ */
    if (daemonize_mode && !cfg.dry_run) {
        if (daemonize() < 0) {
            log_msg(LOG_ERR, "守护化失败，退出");
            return 1;
        }
        /* 重开日志（daemonize 后 PID 变了） */
        closelog();
        openlog("safeshutdown", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    /* ============================================================
     * 第2步：创建心跳文件
     * ============================================================ */
    snprintf(g_heartbeat_path, sizeof(g_heartbeat_path),
             "/tmp/safeshutdown_%d.heartbeat", getpid());
    g_heartbeat_fd = open(g_heartbeat_path,
                          O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (g_heartbeat_fd < 0) {
        log_msg(LOG_ERR, "无法创建心跳文件 %s", g_heartbeat_path);
    }

    /* ============================================================
     * 第3步：fork 看门狗子进程
     * 子进程独立监控主进程心跳，主进程挂掉时触发紧急关机。
     * ============================================================ */
    g_watchdog_pid = fork();
    if (g_watchdog_pid < 0) {
        log_msg(LOG_ERR, "fork 看门狗子进程失败: %s", strerror(errno));
    } else if (g_watchdog_pid == 0) {
        /* 子进程：看门狗（从此与主进程分道扬镳） */
        watchdog_child_loop();
        /* 不会到达这里 */
    }

    log_msg(LOG_INFO, "看门狗子进程 PID: %d", (int)g_watchdog_pid);

    /* ============================================================
     * 第4步：启动看门狗 feeder 线程（用于 /dev/watchdog）
     * ============================================================ */
    pthread_t wdt_thread;
    int pret = pthread_create(&wdt_thread, NULL, watchdog_feeder_thread, NULL);
    if (pret != 0) {
        log_msg(LOG_ERR, "创建看门狗线程失败: %s (err=%d)", strerror(pret), pret);
    } else {
        pthread_detach(wdt_thread);
    }

    /* ============================================================
     * 第5步：初始化 OOM 计数
     * ============================================================ */
    g_oom_last = get_oom_kills();
    if (g_oom_last < 0) g_oom_last = 0;

    log_msg(LOG_INFO, "监护程序已启动 (PID: %d)", getpid());

    /* ---- 主监控循环 ---- */
    while (g_running) {
        long long cycle_start = now_ms();

        /* 更新心跳（通知看门狗子进程我们还活着） */
        update_heartbeat();

        /* 健康检查 */
        health_check();

        /* 告警升级与自动升级逻辑 */
        int level = get_level();
        if (level >= 2) {
            g_escalation_persist++;

            /* 自动升级规则：
             * - 连续 15 个周期仍为 CRITICAL(2) → 升级到 EMERGENCY(3)
             *   （约 30 秒持续异常，排除临时尖峰）
             * - EMERGENCY(3) 持续执行关机流程
             * - PANIC(4) 使用最后手段 */
            if (level == 2 && g_escalation_persist >= 15) {
                log_msg(LOG_CRIT, "CRITICAL 状态持续 %d 个周期，自动升级到 EMERGENCY",
                        g_escalation_persist);
                set_level(3);
                level = 3;
            }

            execute_escalation(level);

            /* 达到最高级别后，不再 sleep，持续尝试关机 */
            if (level >= 4) {
                sleep(5);
                continue;
            }
        } else {
            g_escalation_persist = 0;
        }

        /* 计算需要睡眠的时间，确保固定间隔 */
        long long elapsed = now_ms() - cycle_start;
        long long sleep_ms = cfg.check_interval_ms - elapsed;
        if (sleep_ms > 0) {
            usleep((useconds_t)(sleep_ms * 1000));
        } else if (elapsed > cfg.check_interval_ms * 3 && get_level() == 0) {
            log_msg(LOG_WARNING, "检测周期耗时 %lldms（间隔 %dms），系统可能已过载",
                    elapsed, cfg.check_interval_ms);
        }
    }

    /* ---- 清理 ---- */
    log_msg(LOG_INFO, "safeshutdown 正常退出");

    /* 通知看门狗子进程退出 */
    if (g_watchdog_pid > 0) {
        kill(g_watchdog_pid, SIGTERM);
        /* 等待看门狗子进程退出 */
        int wstatus;
        waitpid(g_watchdog_pid, &wstatus, 0);
    }

    /* 清理心跳文件 */
    if (g_heartbeat_fd >= 0) {
        close(g_heartbeat_fd);
        unlink(g_heartbeat_path);
    }

    closelog();
    return 0;
}
