#include "bar_file.h"
#include "bar_srv.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#define BACKUP_ROOT "/mnt/usb0/PS5/EXPORT/BACKUP"
#define LOG_PATH BACKUP_ROOT "/crossfw_aad12.log"

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

static void dump_diag(const char *stage) {
    const bar_diag_result *d = bar_get_last_diag();
    int32_t status32 = (int32_t)(uint32_t)d->status;
    log_line("[BAR] %-24s request=0x%08lx ioctl_ret=%d errno=%d status=0x%016lx status32=%d context=%d\n",
             stage, d->request, d->ioctl_ret, d->ioctl_errno,
             (unsigned long)d->status, status32, d->context);
}

static int read_exact(int fd, void *buf, size_t size) {
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, p + done, size - done);
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static int is_regular_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int find_archive(char *out, size_t out_size) {
    snprintf(out, out_size, BACKUP_ROOT "/archive.dat");
    if (is_regular_file(out))
        return 0;

    DIR *dir = opendir(BACKUP_ROOT);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        char candidate[512];
        snprintf(candidate, sizeof(candidate), BACKUP_ROOT "/%s/archive.dat", ent->d_name);
        if (is_regular_file(candidate)) {
            snprintf(out, out_size, "%s", candidate);
            closedir(dir);
            return 0;
        }
    }
    closedir(dir);
    return -1;
}

int main(void) {
    char archive_path[512];
    int fd = -1;
    int context = 0;
    int ret = -1;
    int exit_code = 1;
    bar_file_header header;
    bar_file_header aad_header;
    bar_file_segment_metadata *metadata = NULL;
    bar_file_segment_hash *hashes = NULL;
    uint8_t complete_hash[0x20];

    memset(&header, 0, sizeof(header));
    memset(&aad_header, 0, sizeof(aad_header));
    memset(complete_hash, 0, sizeof(complete_hash));

    log_file = fopen(LOG_PATH, "w");
    log_line("=== ps5-bar-tool crossfw AAD-v12 probe ===\n");
    log_line("READ-ONLY: archive bytes are never modified.\n");
    log_line("Test: context_init version=12, while an in-memory copy of the header is changed from version 13 to 12 before AAD.\n");

    if (find_archive(archive_path, sizeof(archive_path)) != 0) {
        log_line("Could not find archive.dat below %s\n", BACKUP_ROOT);
        goto cleanup;
    }

    log_line("Archive: %s\n", archive_path);
    fd = open(archive_path, O_RDONLY);
    if (fd < 0) {
        log_line("open archive failed errno=%d\n", errno);
        goto cleanup;
    }

    if (read_exact(fd, &header, sizeof(header)) != 0) {
        log_line("Failed to read header\n");
        goto cleanup;
    }
    if (*(uint64_t *)&header.magic != 0x464143454953ULL) {
        log_line("Invalid BAR magic\n");
        goto cleanup;
    }
    if (header.n_segments == 0 || header.n_segments > 100000) {
        log_line("Suspicious segment count: %lu\n", (unsigned long)header.n_segments);
        goto cleanup;
    }

    size_t metadata_size = sizeof(*metadata) * (size_t)header.n_segments;
    size_t hashes_size = sizeof(*hashes) * (size_t)header.n_segments;
    metadata = calloc((size_t)header.n_segments, sizeof(*metadata));
    hashes = calloc((size_t)header.n_segments, sizeof(*hashes));
    if (!metadata || !hashes) {
        log_line("Allocation failed\n");
        goto cleanup;
    }

    if (read_exact(fd, metadata, metadata_size) != 0 ||
        read_exact(fd, hashes, hashes_size) != 0 ||
        read_exact(fd, complete_hash, sizeof(complete_hash)) != 0) {
        log_line("Failed to read BAR tables/auth area\n");
        goto cleanup;
    }

    log_line("Disk header version=%d mode=%d segments=%lu\n",
             header.version, header.mode, (unsigned long)header.n_segments);

    if (header.version != 13)
        log_line("WARNING: expected a version-13 BAR, got version=%d; test will still run.\n", header.version);

    aad_header = header;
    aad_header.version = 12;
    log_line("AAD header copy version changed in RAM: %d -> %d\n", header.version, aad_header.version);

    ret = bar_context_create(&context);
    dump_diag("context_create");
    if (ret != 0)
        goto cleanup;

    ret = bar_context_init(context, 12, header.mode, header.key, header.iv);
    dump_diag("context_init_v12");
    if (ret != 0) {
        log_line("RESULT: V12_INIT_REJECTED ret=%d\n", ret);
        goto cleanup;
    }

    ret = bar_update_aad(context, &aad_header, sizeof(aad_header));
    dump_diag("aad_header_ram_v12");
    if (ret != 0)
        goto cleanup;

    ret = bar_update_aad(context, metadata, (int)metadata_size);
    dump_diag("aad_metadata");
    if (ret != 0)
        goto cleanup;

    ret = bar_update_aad(context, hashes, (int)hashes_size);
    dump_diag("aad_hashes");
    if (ret != 0)
        goto cleanup;

    ret = bar_finish_decrypt(context, complete_hash);
    dump_diag("finish_decrypt");
    if (ret == 0)
        log_line("RESULT: HEADER_AUTH_ACCEPTED_WITH_RAM_HEADER_V12\n");
    else
        log_line("RESULT: HEADER_AUTH_REJECTED_WITH_RAM_HEADER_V12 ret=%d\n", ret);

    exit_code = 0;

cleanup:
    if (context) {
        int destroy_ret = bar_context_destroy(context);
        dump_diag("context_destroy");
        if (destroy_ret != 0)
            log_line("context_destroy returned %d\n", destroy_ret);
    }
    close_bar_fd();
    if (fd >= 0)
        close(fd);
    free(metadata);
    free(hashes);
    if (log_file)
        fclose(log_file);
    return exit_code;
}
