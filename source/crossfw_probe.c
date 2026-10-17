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
#define LOG_PATH BACKUP_ROOT "/crossfw_matrix.log"

static FILE *log_file = NULL;

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
             stage,
             d->request,
             d->ioctl_ret,
             d->ioctl_errno,
             (unsigned long)d->status,
             status32,
             d->context);
}

static int read_exact(int fd, void *buf, size_t size) {
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, p + done, size - done);
        if (n < 0)
            return -1;
        if (n == 0)
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

static void print_hex(const char *label, const uint8_t *buf, size_t size) {
    log_line("%s", label);
    for (size_t i = 0; i < size; i++)
        log_line("%02X", buf[i]);
    log_line("\n");
}

static int run_version_probe(
    int test_version,
    const bar_file_header *header,
    const bar_file_segment_metadata *metadata,
    size_t metadata_size,
    const bar_file_segment_hash *hashes,
    size_t hashes_size,
    const uint8_t complete_hash[0x20]
) {
    int context = 0;
    int ret = -1;
    char stage[64];

    log_line("\n=== MATRIX TEST: context version=%d (archive header version=%d) ===\n",
             test_version, header->version);
    log_line("Only the version argument passed to context_init is changed. BAR bytes/AAD remain untouched.\n");

    ret = bar_context_create(&context);
    snprintf(stage, sizeof(stage), "v%d context_create", test_version);
    dump_diag(stage);
    if (ret != 0) {
        log_line("RESULT[v%d]: CONTEXT_CREATE_REJECTED ret=%d\n", test_version, ret);
        goto cleanup;
    }

    ret = bar_context_init(context, test_version, header->mode, (uint8_t *)header->key, (uint8_t *)header->iv);
    snprintf(stage, sizeof(stage), "v%d context_init", test_version);
    dump_diag(stage);
    if (ret != 0) {
        log_line("RESULT[v%d]: INIT_REJECTED ret=%d\n", test_version, ret);
        goto cleanup;
    }

    log_line("RESULT[v%d]: INIT_ACCEPTED\n", test_version);

    ret = bar_update_aad(context, (void *)header, sizeof(*header));
    snprintf(stage, sizeof(stage), "v%d aad_header", test_version);
    dump_diag(stage);
    if (ret != 0) {
        log_line("RESULT[v%d]: AAD_HEADER_REJECTED ret=%d\n", test_version, ret);
        goto cleanup;
    }

    ret = bar_update_aad(context, (void *)metadata, (int)metadata_size);
    snprintf(stage, sizeof(stage), "v%d aad_metadata", test_version);
    dump_diag(stage);
    if (ret != 0) {
        log_line("RESULT[v%d]: AAD_METADATA_REJECTED ret=%d\n", test_version, ret);
        goto cleanup;
    }

    ret = bar_update_aad(context, (void *)hashes, (int)hashes_size);
    snprintf(stage, sizeof(stage), "v%d aad_hashes", test_version);
    dump_diag(stage);
    if (ret != 0) {
        log_line("RESULT[v%d]: AAD_HASHES_REJECTED ret=%d\n", test_version, ret);
        goto cleanup;
    }

    ret = bar_finish_decrypt(context, (uint8_t *)complete_hash);
    snprintf(stage, sizeof(stage), "v%d finish_decrypt", test_version);
    dump_diag(stage);
    if (ret == 0)
        log_line("RESULT[v%d]: HEADER_AUTH_ACCEPTED\n", test_version);
    else
        log_line("RESULT[v%d]: HEADER_AUTH_REJECTED ret=%d\n", test_version, ret);

cleanup:
    if (context) {
        int destroy_ret = bar_context_destroy(context);
        snprintf(stage, sizeof(stage), "v%d context_destroy", test_version);
        dump_diag(stage);
        if (destroy_ret != 0)
            log_line("v%d context_destroy returned %d\n", test_version, destroy_ret);
    }

    /* Make each matrix attempt independent and force a fresh /dev/bar open. */
    close_bar_fd();
    return ret;
}

static int add_unique_version(int versions[], int count, int version) {
    for (int i = 0; i < count; i++) {
        if (versions[i] == version)
            return count;
    }
    versions[count++] = version;
    return count;
}

int main(void) {
    char archive_path[512];
    int fd = -1;
    int exit_code = 1;
    bar_file_header header;
    bar_file_segment_metadata *metadata = NULL;
    bar_file_segment_hash *hashes = NULL;
    uint8_t complete_hash[0x20];

    memset(&header, 0, sizeof(header));
    memset(complete_hash, 0, sizeof(complete_hash));

    /* Start a fresh log on every launch so results from different BARs cannot mix. */
    log_file = fopen(LOG_PATH, "w");

    log_line("=== ps5-bar-tool crossfw version matrix ===\n");
    log_line("Read-only BAR test. The archive itself is never modified.\n");

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
        log_line("Failed to read BAR header errno=%d\n", errno);
        goto cleanup;
    }

    if (*(uint64_t *)&header.magic != 0x464143454953ULL) {
        log_line("Invalid BAR magic\n");
        goto cleanup;
    }

    log_line("Header sizeof=0x%lx mode=%d version=%d segments=%lu data_offset=0x%lx data_size=0x%lx\n",
             (unsigned long)sizeof(header),
             header.mode,
             header.version,
             (unsigned long)header.n_segments,
             (unsigned long)header.data_offset,
             (unsigned long)header.data_size);
    print_hex("Header key arg: ", header.key, sizeof(header.key));
    print_hex("Header IV arg : ", header.iv, sizeof(header.iv));

    if (header.n_segments == 0 || header.n_segments > 100000) {
        log_line("Refusing suspicious segment count: %lu\n", (unsigned long)header.n_segments);
        goto cleanup;
    }

    metadata = calloc((size_t)header.n_segments, sizeof(*metadata));
    hashes = calloc((size_t)header.n_segments, sizeof(*hashes));
    if (!metadata || !hashes) {
        log_line("Allocation failed\n");
        goto cleanup;
    }

    size_t metadata_size = sizeof(*metadata) * (size_t)header.n_segments;
    size_t hashes_size = sizeof(*hashes) * (size_t)header.n_segments;

    if (read_exact(fd, metadata, metadata_size) != 0) {
        log_line("Failed to read metadata table errno=%d\n", errno);
        goto cleanup;
    }
    if (read_exact(fd, hashes, hashes_size) != 0) {
        log_line("Failed to read hash table errno=%d\n", errno);
        goto cleanup;
    }
    if (read_exact(fd, complete_hash, sizeof(complete_hash)) != 0) {
        log_line("Failed to read 0x20-byte header auth area errno=%d\n", errno);
        goto cleanup;
    }

    print_hex("Header auth[0:16]: ", complete_hash, 0x10);
    print_hex("Header auth[16:32]: ", complete_hash + 0x10, 0x10);

    int versions[3];
    int version_count = 0;
    version_count = add_unique_version(versions, version_count, header.version);
    version_count = add_unique_version(versions, version_count, 12);
    version_count = add_unique_version(versions, version_count, 13);

    log_line("\n-- /dev/bar compatibility matrix --\n");
    for (int i = 0; i < version_count; i++)
        run_version_probe(versions[i], &header, metadata, metadata_size, hashes, hashes_size, complete_hash);

    log_line("\n=== MATRIX COMPLETE ===\n");
    exit_code = 0;

cleanup:
    close_bar_fd();
    if (fd >= 0)
        close(fd);
    free(metadata);
    free(hashes);
    if (log_file)
        fclose(log_file);

    return exit_code;
}
