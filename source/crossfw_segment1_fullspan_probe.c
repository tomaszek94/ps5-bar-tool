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
#define LOG_PATH BACKUP_ROOT "/crossfw_segment1_fullspan.log"
#define ARCHIVE_PART_SIZE 0xFFFF0000ULL
#define MAX_ALIGNED_SIZE 0x200000ULL

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
    log_line("[BAR] %-28s request=0x%08lx ioctl_ret=%d errno=%d status=0x%016lx status32=%d context=%d\n",
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

static bar_file_segment_hash *find_hash(bar_file_segment_hash *table, uint64_t count, int segment_id) {
    for (uint64_t i = 0; i < count; i++)
        if (table[i].segment_id == segment_id)
            return &table[i];
    return NULL;
}

static void print_hex(const char *label, const uint8_t *buf, size_t size) {
    log_line("%s", label);
    for (size_t i = 0; i < size; i++)
        log_line("%02X", buf[i]);
    log_line("\n");
}

static void hexdump_prefix(const uint8_t *buf, size_t size) {
    size_t limit = size < 0x80 ? size : 0x80;
    for (size_t off = 0; off < limit; off += 16) {
        log_line("%04lx: ", (unsigned long)off);
        for (size_t i = 0; i < 16; i++) {
            if (off + i < limit)
                log_line("%02X ", buf[off + i]);
            else
                log_line("   ");
        }
        log_line(" | ");
        for (size_t i = 0; i < 16 && off + i < limit; i++) {
            uint8_t c = buf[off + i];
            log_line("%c", (c >= 0x20 && c <= 0x7e) ? (char)c : '.');
        }
        log_line("\n");
    }
}

static int probe_archive(const char *archive_path) {
    int fd = -1;
    int context = 0;
    int ret = -1;
    bar_file_header header;
    bar_file_segment_metadata *metadata = NULL;
    bar_file_segment_hash *hashes = NULL;
    uint8_t *encrypted = NULL;
    uint8_t *decrypted = NULL;
    char archive_dir[768];

    memset(&header, 0, sizeof(header));
    parent_dir_from_archive(archive_path, archive_dir, sizeof(archive_dir));

    log_line("\n============================================================\n");
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
        log_line("Suspicious segment count=%lu\n", (unsigned long)header.n_segments);
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
    if (read_exact(fd, metadata, metadata_size) != 0 || read_exact(fd, hashes, hashes_size) != 0) {
        log_line("Failed to read BAR tables\n");
        goto cleanup;
    }

    bar_file_segment_metadata *m = find_metadata(metadata, header.n_segments, 1);
    bar_file_segment_hash *h = find_hash(hashes, header.n_segments, 1);
    if (!m || !h) {
        log_line("Segment 1 metadata/hash not found\n");
        goto cleanup;
    }

    size_t aligned_size = (size_t)m->compressed_size;
    size_t actual_size = (size_t)m->uncompressed_size;
    log_line("Header protocol version=%d mode=%d\n", header.version, header.mode);
    log_line("Segment1 offset=0x%lx aligned=0x%lx actual=0x%lx\n",
             (unsigned long)m->data_offset,
             (unsigned long)m->compressed_size,
             (unsigned long)m->uncompressed_size);
    print_hex("Segment1 IV  : ", m->iv, sizeof(m->iv));
    print_hex("Segment1 tag : ", h->hash, sizeof(h->hash));

    if (aligned_size == 0 || aligned_size > MAX_ALIGNED_SIZE || actual_size == 0 || actual_size > aligned_size) {
        log_line("Refusing suspicious segment lengths.\n");
        goto cleanup;
    }

    encrypted = malloc(aligned_size);
    decrypted = calloc(1, aligned_size);
    if (!encrypted || !decrypted) {
        log_line("Buffer allocation failed\n");
        goto cleanup;
    }
    if (read_logical(archive_dir, m->data_offset, encrypted, aligned_size) != 0) {
        log_line("Failed to read full aligned segment span.\n");
        goto cleanup;
    }

    ret = bar_context_create(&context);
    dump_diag("context_create");
    if (ret != 0)
        goto cleanup;

    ret = bar_context_init(context, 12, header.mode, header.key, m->iv);
    dump_diag("context_init_forced_v12");
    if (ret != 0) {
        log_line("RESULT: INIT_REJECTED ret=%d\n", ret);
        goto cleanup;
    }

    ret = bar_update_decrypt(context, decrypted, encrypted, (int)aligned_size);
    dump_diag("decrypt_full_aligned_span");
    if (ret != 0) {
        log_line("RESULT: FULLSPAN_DECRYPT_REJECTED ret=%d\n", ret);
        goto cleanup;
    }
    log_line("RESULT: FULLSPAN_DECRYPT_CALL_ACCEPTED\n");

    ret = bar_finish_decrypt(context, h->hash);
    dump_diag("finish_fullspan_tag");
    if (ret == 0)
        log_line("RESULT: FULLSPAN_TAG_ACCEPTED\n");
    else
        log_line("RESULT: FULLSPAN_TAG_REJECTED ret=%d\n", ret);

    log_line("Plaintext prefix (first 0x80 bytes; actual data length=0x%lx):\n", (unsigned long)actual_size);
    hexdump_prefix(decrypted, actual_size);
    if (actual_size >= 4)
        log_line("Magic candidate: %c%c%c%c\n", decrypted[0], decrypted[1], decrypted[2], decrypted[3]);

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
    return ret;
}

int main(void) {
    int found = 0;
    log_file = fopen(LOG_PATH, "w");
    log_line("=== ps5-bar-tool segment-1 full-aligned-span probe ===\n");
    log_line("READ-ONLY. Tests whether segment authentication covers the aligned section span.\n");
    log_line("All archives are initialized with /dev/bar protocol version 12.\n");

    DIR *dir = opendir(BACKUP_ROOT);
    if (!dir) {
        log_line("Could not open %s errno=%d\n", BACKUP_ROOT, errno);
        if (log_file)
            fclose(log_file);
        return 1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        char path[768];
        snprintf(path, sizeof(path), BACKUP_ROOT "/%s/archive.dat", ent->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            found++;
            probe_archive(path);
        }
    }
    closedir(dir);

    log_line("\n=== COMPLETE: archives tested=%d ===\n", found);
    if (log_file)
        fclose(log_file);
    return found > 0 ? 0 : 1;
}
