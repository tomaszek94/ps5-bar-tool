#include "bar_srv.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

int bar_fd = -1;
static bar_diag_result last_diag;

static void record_diag(unsigned long request, int ret, int saved_errno, bar_args* args) {
    last_diag.request = request;
    last_diag.ioctl_ret = ret;
    last_diag.ioctl_errno = saved_errno;
    last_diag.status = args ? args->status : 0;
    last_diag.context = args ? args->context : 0;
}

const bar_diag_result* bar_get_last_diag(void) {
    return &last_diag;
}

int get_bar_fd (void) {
    if (bar_fd == -1) {
        errno = 0;
        bar_fd = open("/dev/bar", O_RDWR, 0);
        if (bar_fd < 0)
        {
            int saved_errno = errno;
            memset(&last_diag, 0, sizeof(last_diag));
            last_diag.ioctl_ret = -1;
            last_diag.ioctl_errno = saved_errno;
            printf("Failed to open '/dev/bar' errno=%d\n", saved_errno);
        }
    }
    return bar_fd;
}

int close_bar_fd (void) {
    if (bar_fd != -1) {
        int ret = close(bar_fd);
        bar_fd = -1;
        return ret;
    }
    return 0;
}

int bar_context_create (int* context) {
    int ret;
    int saved_errno;
    bar_args args;

    memset(&args, 0, sizeof(args));

    int fd = get_bar_fd();
    if (fd < 0)
        return -1;

    errno = 0;
    ret = ioctl(fd,0xc0684201, &args);
    saved_errno = errno;
    record_diag(0xc0684201, ret, saved_errno, &args);
    if (ret == 0) {
        *context = args.context;
    }
    return ret;
}

int bar_context_destroy (int context) {
    int ret;
    int saved_errno;
    bar_args args;

    memset(&args, 0, sizeof(args));
    args.context = context;

    int fd = get_bar_fd();
    if (fd < 0)
        return -1;

    errno = 0;
    ret = ioctl(fd,0xc0684202, &args);
    saved_errno = errno;
    record_diag(0xc0684202, ret, saved_errno, &args);
    return ret;
}

int bar_context_init (int context, int version, int mode, uint8_t key[16], uint8_t iv[12]) {
    int ret;
    int saved_errno;
    bar_args args;

    memset(&args, 0, sizeof(args));
    args.context = context;
    args.version = version;
    args.mode = mode;
    memcpy(&args.key, key, 16);
    memcpy(&args.iv, iv, 12);

    int fd = get_bar_fd();
    if (fd < 0)
        return -1;

    errno = 0;
    ret = ioctl(fd,0xc0684203, &args);
    saved_errno = errno;
    record_diag(0xc0684203, ret, saved_errno, &args);
    if (ret == 0) {
        ret = (int) args.status;
    }
    return ret;
}

int bar_update_aad (int context, void* buf, int size) {
    int ret;
    int saved_errno;
    bar_args args;

    memset(&args, 0, sizeof(args));
    args.context = context;
    args.aad_source = buf;
    args.aad_size = size;

    int fd = get_bar_fd();
    if (fd < 0)
        return -1;

    errno = 0;
    ret = ioctl(fd,0xc0684204, &args);
    saved_errno = errno;
    record_diag(0xc0684204, ret, saved_errno, &args);
    if (ret == 0) {
        ret = (int) args.status;
    }
    return ret;
}

int bar_update_encrypt (int context, void* dest, void* source, int size) {
    int ret = 0;
    int saved_errno;
    bar_args args;
    int chuck_size = 0;
    void* tmp_dest = dest;
    void* tmp_source = source;

    memset(&args, 0, sizeof(args));
    args.context = context;

    do {

        if (size > 0x40000) {
            chuck_size = 0x40000;
        }
        else {
            chuck_size = size;
        }

        args.enc_dec_source = tmp_source;
        args.enc_dec_dest = tmp_dest;
        args.enc_dec_size = chuck_size;

        int fd = get_bar_fd();
        if (fd < 0)
            return -1;

        errno = 0;
        ret = ioctl(fd,0xc0684205, &args);
        saved_errno = errno;
        record_diag(0xc0684205, ret, saved_errno, &args);
        if (ret == 0) {
            ret = (int) args.status;
        }
        if (ret != 0)
            break;

        size = size - chuck_size;
        tmp_source = tmp_source + chuck_size;
        tmp_dest = tmp_dest + chuck_size;

    } while (size);
    return ret;
}

int bar_update_decrypt (int context, void* dest, void* source, int size) {
    int ret = 0;
    int saved_errno;
    bar_args args;
    int chuck_size = 0;
    void* tmp_dest = dest;
    void* tmp_source = source;

    memset(&args, 0, sizeof(args));
    args.context = context;

    do {

        if (size > 0x40000) {
            chuck_size = 0x40000;
        }
        else {
            chuck_size = size;
        }

        args.enc_dec_source = tmp_source;
        args.enc_dec_dest = tmp_dest;
        args.enc_dec_size = chuck_size;

        int fd = get_bar_fd();
        if (fd < 0)
            return -1;

        errno = 0;
        ret = ioctl(fd,0xc0684206, &args);
        saved_errno = errno;
        record_diag(0xc0684206, ret, saved_errno, &args);
        if (ret == 0) {
            ret = (int) args.status;
        }
        if (ret != 0)
            break;

        size = size - chuck_size;
        tmp_source = tmp_source + chuck_size;
        tmp_dest = tmp_dest + chuck_size;

    } while (size);

    return ret;
}

int bar_finish_encrypt (int context, uint8_t hash[16]) {
    int ret;
    int saved_errno;
    bar_args args;

    memset(&args, 0, sizeof(args));
    args.context = context;

    int fd = get_bar_fd();
    if (fd < 0)
        return -1;

    errno = 0;
    ret = ioctl(fd,0xc0684207, &args);
    saved_errno = errno;
    record_diag(0xc0684207, ret, saved_errno, &args);
    if (ret == 0) {
        memcpy(hash, &args.hash, 16);
        ret = (int) args.status;
    }
    return ret;
}

int bar_finish_decrypt (int context, uint8_t hash[16]) {
    int ret;
    int saved_errno;
    bar_args args;

    memset(&args, 0, sizeof(args));
    args.context = context;
    memcpy(&args.hash, hash, 16);

    int fd = get_bar_fd();
    if (fd < 0)
        return -1;

    errno = 0;
    ret = ioctl(fd,0xc0684208, &args);
    saved_errno = errno;
    record_diag(0xc0684208, ret, saved_errno, &args);

    if (ret == 0) {
        ret = (int) args.status;
    }
    return ret;
}
