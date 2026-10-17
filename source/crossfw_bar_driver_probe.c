#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>

#define LOG_PATH "/mnt/usb0/PS5/EXPORT/BACKUP/crossfw_bar_driver_probe.log"
#define MAX_KLDS 512
#define MAX_MODS 2048

static FILE *log_file;

static void log_line(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    if (log_file) {
        va_start(args, fmt);
        vfprintf(log_file, fmt, args);
        va_end(args);
        fflush(log_file);
    }
}

static void probe_bar_device(void) {
    log_line("-- /dev/bar stat --\n");

    errno = 0;
    int fd = open("/dev/bar", O_RDWR);
    if (fd < 0) {
        log_line("open('/dev/bar', O_RDWR) failed errno=%d\n", errno);
        return;
    }

    log_line("open('/dev/bar', O_RDWR): fd=%d\n", fd);

    struct stat st;
    memset(&st, 0, sizeof(st));
    errno = 0;
    if (fstat(fd, &st) == 0) {
        log_line("fstat: st_dev=0x%llx st_ino=0x%llx st_mode=0x%llx st_rdev=0x%llx st_size=0x%llx\n",
                 (unsigned long long)st.st_dev,
                 (unsigned long long)st.st_ino,
                 (unsigned long long)st.st_mode,
                 (unsigned long long)st.st_rdev,
                 (unsigned long long)st.st_size);
    } else {
        log_line("fstat failed errno=%d\n", errno);
    }

    close(fd);
    log_line("\n");
}

static void probe_klds(void) {
    log_line("-- kldnext/kldstat inventory --\n");

    int current = 0;
    int count = 0;

    for (int guard = 0; guard < MAX_KLDS; guard++) {
        errno = 0;
        int next = kldnext(current);
        if (next <= 0) {
            log_line("kldnext(%d) -> %d errno=%d; enumeration finished\n", current, next, errno);
            break;
        }

        struct kld_file_stat ks;
        memset(&ks, 0, sizeof(ks));
        ks.version = sizeof(ks);

        errno = 0;
        int ret = kldstat(next, &ks);
        if (ret == 0) {
            log_line("KLD id=%d refs=%d addr=%p size=0x%llx name='%s' path='%s'\n",
                     ks.id,
                     ks.refs,
                     (void *)ks.address,
                     (unsigned long long)ks.size,
                     ks.name,
                     ks.pathname);
        } else {
            log_line("KLD id=%d kldstat ret=%d errno=%d\n", next, ret, errno);
        }

        current = next;
        count++;
    }

    log_line("KLD entries visited=%d\n\n", count);
}

static void probe_modules(void) {
    log_line("-- modnext/modstat inventory --\n");

    int current = 0;
    int count = 0;

    for (int guard = 0; guard < MAX_MODS; guard++) {
        errno = 0;
        int next = modnext(current);
        if (next <= 0) {
            log_line("modnext(%d) -> %d errno=%d; enumeration finished\n", current, next, errno);
            break;
        }

        struct module_stat ms;
        memset(&ms, 0, sizeof(ms));
        ms.version = sizeof(ms);

        errno = 0;
        int ret = modstat(next, &ms);
        if (ret == 0) {
            log_line("MOD id=%d refs=%d data=0x%llx name='%s'\n",
                     ms.id,
                     ms.refs,
                     (unsigned long long)ms.data.ulongval,
                     ms.name);
        } else {
            log_line("MOD id=%d modstat ret=%d errno=%d\n", next, ret, errno);
        }

        current = next;
        count++;
    }

    log_line("Module entries visited=%d\n\n", count);
}

int main(void) {
    log_file = fopen(LOG_PATH, "w");

    log_line("=== ps5-bar-tool BAR driver/module inventory probe ===\n");
    log_line("READ-ONLY: opens /dev/bar only for fstat and enumerates FreeBSD linker/module metadata.\n");
    log_line("No BAR ioctl is issued and no archive is touched.\n\n");

    probe_bar_device();
    probe_klds();
    probe_modules();

    log_line("=== PROBE COMPLETE ===\n");

    if (log_file)
        fclose(log_file);

    return 0;
}
