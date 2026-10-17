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
#define LOG_PATH BACKUP_ROOT "/crossfw_segment1_version_sweep.log"
#define ARCHIVE_PART_SIZE 0xFFFF0000ULL
#define MAX_ACTUAL_SIZE 0x100000ULL

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

static void parent_dir_from_archive(const char *archive_path, char *out, size_t out_size) {
    snprintf(out, out_size, "%s", archive_path);
    char *slash = strrchr(out, '/');
    if (slash)
        *slash = '\0';
}

static int read_logical(const char *archive_dir, uint64_t logical_offset, void *buf, size_t size) {
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;

    while (done < size) {
        uint64_t off = logical_offset + done;
        uint64_t part = off / ARCHIVE_PART_SIZE;
        uint64_t local = off % ARCHIVE_PART_SIZE;
        uint64_t room = ARCHIVE_PART_SIZE - local;
        size_t chunk = size - done;
        if ((uint64_t)chunk > room)
            chunk = (size_t)room;

        char path[768];
        if (part == 0)
            snprintf(path, sizeof(path), "%s/archive.dat", archive_dir);
        else
            snprintf(path, sizeof(path), "%s/archive%04lu.dat", archive_dir, (unsigned long)part);

        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            log_line("Failed to open %s errno=%d\n", path, errno);
            return -1;
        }
        int rr = pread_exact(fd, dst + done, chunk, local);
        close(fd);
        if (rr != 0) {
            log_line("Failed read %s local=0x%lx size=0x%lx errno=%d\n",
                     path, (unsigned long)local, (unsigned long)chunk, errno);
            return -1;
        }
        done += chunk;
    }
    return 0;
}

static bar_file_segment_metadata *find_metadata(bar_file_segment_metadata *table, uint64_t count, int segment_id) {
    for (uint64_t i = 0; i < count; i++)
        if (table[i].segment_id == segment_id)
            return &table[i];
    return NULL;
}

static int find_v13_archive(char *out, size_t out_size) {
    DIR *dir = opendir(BACKUP_ROOT);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;

        char path[768];
        snprintf(path, sizeof(path), BACKUP_ROOT "/%s/archive.dat", ent->d_name);
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        bar_file_header h;
        memset(&h, 0, sizeof(h));
        int ok = read_exact(fd, &h, sizeof(h));
        close(fd);
        if (ok == 0 && *(uint64_t *)&h.magic == 0x464143454953ULL && h.version == 13) {
            snprintf(out, out_size, "%s", path);
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -1;
}

static void print_first16(const uint8_t *buf, size_t size) {
    size_t n = size < 16 ? size : 16;
    for (size_t i = 0; i < n; i++)
        log_line("%02X", buf[i]);
}

int main(void) {
    char archive_path[768];
    char archive_dir[768];
    int fd = -1;
    int exit_code = 1;
    bar_file_header header;
    bar_file_segment_metadata *metadata = NULL;
    uint8_t *encrypted = NULL;
    uint8_t *decrypted = NULL;

    log_file = fopen(LOG_PATH, "w");
    log_line("=== ps5-bar-tool v13 segment-1 protocol version sweep ===\n");
    log_line("READ-ONLY. No BAR bytes are modified.\n");
    log_line("Tests /dev/bar context versions 1..13 against the same v13 segment-1 ciphertext.\n");
    log_line("Success criterion: plaintext begins with ASCII P5BR.\n\n");

    if (find_v13_archive(archive_path, sizeof(archive_path)) != 0) {
        log_line("Could not find a version-13 archive.dat below %s\n", BACKUP_ROOT);
        goto cleanup;
    }

    parent_dir_from_archive(archive_path, archive_dir, sizeof(archive_dir));
    log_line("Archive: %s\n", archive_path);

    fd = open(archive_path, O_RDONLY);
    if (fd < 0) {
        log_line("open failed errno=%d\n", errno);
        goto cleanup;
    }

    memset(&header, 0, sizeof(header));
    if (read_exact(fd, &header, sizeof(header)) != 0) {
        log_line("Failed to read BAR header\n");
        goto cleanup;
    }
    if (header.n_segments == 0 || header.n_segments > 100000) {
        log_line("Suspicious segment count=%lu\n", (unsigned long)header.n_segments);
        goto cleanup;
    }

    metadata = calloc((size_t)header.n_segments, sizeof(*metadata));
    if (!metadata) {
        log_line("Metadata allocation failed\n");
        goto cleanup;
    }
    size_t metadata_size = sizeof(*metadata) * (size_t)header.n_segments;
    if (read_exact(fd, metadata, metadata_size) != 0) {
        log_line("Failed to read metadata table\n");
        goto cleanup;
    }

    bar_file_segment_metadata *m = find_metadata(metadata, header.n_segments, 1);
    if (!m) {
        log_line("Segment 1 not found\n");
        goto cleanup;
    }

    size_t actual_size = (size_t)m->uncompressed_size;
    if (actual_size == 0 || actual_size > MAX_ACTUAL_SIZE) {
        log_line("Refusing actual size 0x%lx\n", (unsigned long)actual_size);
        goto cleanup;
    }

    encrypted = malloc(actual_size);
    decrypted = malloc(actual_size);
    if (!encrypted || !decrypted) {
        log_line("Buffer allocation failed\n");
        goto cleanup;
    }

    if (read_logical(archive_dir, m->data_offset, encrypted, actual_size) != 0) {
        log_line("Failed to read v13 segment 1 bytes\n");
        goto cleanup;
    }

    log_line("Header version=%d mode=%d segment1_offset=0x%lx actual=0x%lx\n",
             header.version, header.mode,
             (unsigned long)m->data_offset,
             (unsigned long)m->uncompressed_size);
    log_line("Segment1 IV=");
    for (size_t i = 0; i < sizeof(m->iv); i++)
        log_line("%02X", m->iv[i]);
    log_line("\n\n");

    int hits = 0;

    for (int version = 1; version <= 13; version++) {
        int context = 0;
        int ret;
        memset(decrypted, 0, actual_size);

        ret = bar_context_create(&context);
        const bar_diag_result *d = bar_get_last_diag();
        if (ret != 0) {
            log_line("v%02d create: ret=%d ioctl=%d errno=%d status32=%d\n",
                     version, ret, d->ioctl_ret, d->ioctl_errno,
                     (int32_t)(uint32_t)d->status);
            close_bar_fd();
            continue;
        }

        ret = bar_context_init(context, version, header.mode, header.key, m->iv);
        d = bar_get_last_diag();
        if (ret != 0) {
            log_line("v%02d init: REJECT ret=%d ioctl=%d errno=%d status32=%d\n",
                     version, ret, d->ioctl_ret, d->ioctl_errno,
                     (int32_t)(uint32_t)d->status);
            bar_context_destroy(context);
            close_bar_fd();
            continue;
        }

        ret = bar_update_decrypt(context, decrypted, encrypted, (int)actual_size);
        d = bar_get_last_diag();
        if (ret != 0) {
            log_line("v%02d decrypt: REJECT ret=%d ioctl=%d errno=%d status32=%d\n",
                     version, ret, d->ioctl_ret, d->ioctl_errno,
                     (int32_t)(uint32_t)d->status);
        } else {
            int p5br = actual_size >= 4 && memcmp(decrypted, "P5BR", 4) == 0;
            log_line("v%02d decrypt: OK first16=", version);
            print_first16(decrypted, actual_size);
            log_line(" magic=%c%c%c%c %s\n",
                     actual_size > 0 ? decrypted[0] : '.',
                     actual_size > 1 ? decrypted[1] : '.',
                     actual_size > 2 ? decrypted[2] : '.',
                     actual_size > 3 ? decrypted[3] : '.',
                     p5br ? "<<< P5BR HIT" : "");
            if (p5br)
                hits++;
        }

        bar_context_destroy(context);
        close_bar_fd();
    }

    log_line("\n=== SWEEP COMPLETE: P5BR hits=%d ===\n", hits);
    exit_code = 0;

cleanup:
    close_bar_fd();
    if (fd >= 0)
        close(fd);
    free(metadata);
    free(encrypted);
    free(decrypted);
    if (log_file)
        fclose(log_file);
    return exit_code;
}
