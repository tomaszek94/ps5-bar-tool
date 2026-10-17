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
#define LOG_PATH BACKUP_ROOT "/crossfw_segment1_v12.log"
#define FIRST_ARCHIVE_SIZE 0xFFFF0000ULL
#define MAX_TEST_SIZE 0x100000ULL

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
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static int pread_exact(int fd, void *buf, size_t size, uint64_t offset) {
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, p + done, size - done, (off_t)(offset + done));
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

static void print_hex(const char *label, const uint8_t *buf, size_t size) {
    log_line("%s", label);
    for (size_t i = 0; i < size; i++)
        log_line("%02X", buf[i]);
    log_line("\n");
}

static void hexdump(const uint8_t *buf, size_t size) {
    for (size_t off = 0; off < size; off += 16) {
        log_line("%04lx: ", (unsigned long)off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < size)
                log_line("%02X ", buf[off + i]);
            else
                log_line("   ");
        }
        log_line(" | ");
        for (size_t i = 0; i < 16 && off + i < size; i++) {
            uint8_t c = buf[off + i];
            log_line("%c", (c >= 0x20 && c <= 0x7e) ? (char)c : '.');
        }
        log_line("\n");
    }
}

static bar_file_segment_metadata *find_metadata(bar_file_segment_metadata *table, uint64_t count, int segment_id) {
    for (uint64_t i = 0; i < count; i++) {
        if (table[i].segment_id == segment_id)
            return &table[i];
    }
    return NULL;
}

static bar_file_segment_hash *find_hash(bar_file_segment_hash *table, uint64_t count, int segment_id) {
    for (uint64_t i = 0; i < count; i++) {
        if (table[i].segment_id == segment_id)
            return &table[i];
    }
    return NULL;
}

static int32_t read_i32(const uint8_t *buf, size_t size, size_t off) {
    int32_t v = 0;
    if (off + sizeof(v) <= size)
        memcpy(&v, buf + off, sizeof(v));
    return v;
}

static uint64_t read_u64(const uint8_t *buf, size_t size, size_t off) {
    uint64_t v = 0;
    if (off + sizeof(v) <= size)
        memcpy(&v, buf + off, sizeof(v));
    return v;
}

static void log_segment1_fields(const uint8_t *buf, size_t size) {
    if (size < 0x34) {
        log_line("Plaintext too small for segment-1 field probe.\n");
        return;
    }

    int32_t file_version = read_i32(buf, size, 0x04);
    uint32_t sw_version = (uint32_t)read_i32(buf, size, 0x08);
    int32_t total_users = read_i32(buf, size, 0x0c);
    int32_t total_dirs = read_i32(buf, size, 0x10);
    int32_t total_files = read_i32(buf, size, 0x14);
    uint64_t required_hdd = read_u64(buf, size, 0x28);
    int32_t target = read_i32(buf, size, 0x30);

    log_line("\n-- Parsed segment-1 candidate fields --\n");
    log_line("file_version=%d\n", file_version);
    log_line("software_version_raw=0x%08X bytes=%02X.%02X.%02X.%02X\n",
             sw_version,
             (sw_version >> 24) & 0xff,
             (sw_version >> 16) & 0xff,
             (sw_version >> 8) & 0xff,
             sw_version & 0xff);
    log_line("total_users=%d total_dirs=%d total_files=%d\n",
             total_users, total_dirs, total_files);
    log_line("required_hdd_size=%lu target=%d\n",
             (unsigned long)required_hdd, target);

    if (size >= 0x74) {
        char console_name[0x41];
        memset(console_name, 0, sizeof(console_name));
        memcpy(console_name, buf + 0x34, 0x40);
        console_name[0x40] = '\0';
        log_line("console_name_candidate=%s\n", console_name);
    }

    if (size >= 0x178) {
        char description[0x79];
        memset(description, 0, sizeof(description));
        memcpy(description, buf + 0x100, 0x78);
        description[0x78] = '\0';
        log_line("description_candidate=%s\n", description);
    }

    if (total_users > 0 && total_users <= 16 && size >= 0x200 + (size_t)total_users * sizeof(bar_user)) {
        const bar_user *users = (const bar_user *)(buf + 0x200);
        log_line("users:\n");
        for (int i = 0; i < total_users; i++) {
            char name[0x19];
            memset(name, 0, sizeof(name));
            memcpy(name, users[i].user_name, 0x18);
            name[0x18] = '\0';
            log_line("  [%d] id=%08X online=%d name=%s\n",
                     i, (unsigned int)users[i].user_id, users[i].flag_online, name);
        }
    }
}

int main(void) {
    char archive_path[512];
    int fd = -1;
    int context = 0;
    int ret = -1;
    int exit_code = 1;
    bar_file_header header;
    bar_file_segment_metadata *metadata = NULL;
    bar_file_segment_hash *hashes = NULL;
    uint8_t *encrypted = NULL;
    uint8_t *decrypted = NULL;

    memset(&header, 0, sizeof(header));
    log_file = fopen(LOG_PATH, "w");

    log_line("=== ps5-bar-tool crossfw forced-v12 segment-1 probe ===\n");
    log_line("READ-ONLY: archive bytes are never modified.\n");
    log_line("Purpose: test whether a v13 BAR data segment can be decrypted by FW 13.60 using context version 12.\n\n");

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
        log_line("Failed to read BAR header\n");
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
        read_exact(fd, hashes, hashes_size) != 0) {
        log_line("Failed to read BAR tables\n");
        goto cleanup;
    }

    bar_file_segment_metadata *m = find_metadata(metadata, header.n_segments, 1);
    bar_file_segment_hash *h = find_hash(hashes, header.n_segments, 1);
    if (!m) {
        log_line("Segment 1 metadata not found\n");
        goto cleanup;
    }

    log_line("Header version=%d mode=%d\n", header.version, header.mode);
    log_line("Segment 1: id=%d part=%u data_offset=0x%lx compressed=0x%lx uncompressed=0x%lx algorithm_type=%lu algorithm_version=%lu\n",
             m->segment_id,
             (unsigned int)m->part_number,
             (unsigned long)m->data_offset,
             (unsigned long)m->compressed_size,
             (unsigned long)m->uncompressed_size,
             (unsigned long)m->algorithm_type,
             (unsigned long)m->algorithm_version);
    print_hex("Segment 1 IV: ", m->iv, sizeof(m->iv));
    if (h)
        print_hex("Segment 1 auth/hash: ", h->hash, sizeof(h->hash));
    else
        log_line("Segment 1 auth/hash entry not found; tag validation will be skipped.\n");

    if (m->compressed_size == 0 || m->compressed_size > MAX_TEST_SIZE ||
        m->uncompressed_size == 0 || m->uncompressed_size > MAX_TEST_SIZE) {
        log_line("Refusing segment size outside probe limit (max 0x%lx).\n", (unsigned long)MAX_TEST_SIZE);
        goto cleanup;
    }

    if (m->compressed_size != m->uncompressed_size) {
        log_line("REFUSING DECRYPT: compressed_size != uncompressed_size; this probe intentionally avoids guessing compression semantics.\n");
        goto cleanup;
    }

    if (m->data_offset + m->compressed_size > FIRST_ARCHIVE_SIZE) {
        log_line("REFUSING DECRYPT: segment 1 crosses archive.dat boundary; probe only reads the first physical file.\n");
        goto cleanup;
    }

    encrypted = malloc((size_t)m->compressed_size);
    decrypted = calloc(1, (size_t)m->uncompressed_size);
    if (!encrypted || !decrypted) {
        log_line("Buffer allocation failed\n");
        goto cleanup;
    }

    if (pread_exact(fd, encrypted, (size_t)m->compressed_size, m->data_offset) != 0) {
        log_line("Failed reading encrypted segment 1 at offset 0x%lx errno=%d\n",
                 (unsigned long)m->data_offset, errno);
        goto cleanup;
    }

    ret = bar_context_create(&context);
    dump_diag("context_create");
    if (ret != 0)
        goto cleanup;

    ret = bar_context_init(context, 12, header.mode, header.key, m->iv);
    dump_diag("context_init_v12");
    if (ret != 0) {
        log_line("RESULT: V12_SEGMENT_INIT_REJECTED ret=%d\n", ret);
        goto cleanup;
    }

    ret = bar_update_decrypt(context, decrypted, encrypted, (int)m->uncompressed_size);
    dump_diag("segment1_decrypt_v12");
    if (ret != 0) {
        log_line("RESULT: V12_SEGMENT_DECRYPT_REJECTED ret=%d\n", ret);
        goto cleanup;
    }

    log_line("RESULT: V12_SEGMENT_DECRYPT_CALL_ACCEPTED\n");

    if (h) {
        ret = bar_finish_decrypt(context, h->hash);
        dump_diag("segment1_finish_tag");
        if (ret == 0)
            log_line("RESULT: V12_SEGMENT1_AUTH_ACCEPTED\n");
        else
            log_line("RESULT: V12_SEGMENT1_AUTH_REJECTED ret=%d\n", ret);
    }

    size_t dump_size = (size_t)m->uncompressed_size;
    if (dump_size > 0x400)
        dump_size = 0x400;
    log_line("\n-- First 0x%lx bytes of candidate plaintext --\n", (unsigned long)dump_size);
    hexdump(decrypted, dump_size);
    log_segment1_fields(decrypted, (size_t)m->uncompressed_size);

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
    free(encrypted);
    free(decrypted);
    if (log_file)
        fclose(log_file);
    return exit_code;
}
