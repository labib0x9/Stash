#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>

#define MAX_LINE 1024
#define MAX_PATH 256
#define MAX_REGIONS 256

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[8];
    char path[MAX_PATH];
    unsigned char *content;
    size_t size;
} Region;

typedef struct {
    char name[64];
    int threads;
    Region regions[MAX_REGIONS];
    int region_count;
    char *cmdline;
    size_t cmdline_len;
    char *environ;
    size_t environ_len;
    char cwd[MAX_PATH];
} Status;

static char *read_whole_file(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); exit(1); }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }

    /* procfs files often report size 0; use a growable buffer */
    size_t cap = st.st_size > 0 ? (size_t)st.st_size + 1 : 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) { perror("malloc"); exit(1); }

    ssize_t n;
    while ((n = read(fd, buf + len, cap - len)) > 0) {
        len += (size_t)n;
        if (len == cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { perror("realloc"); exit(1); }
            buf = tmp;
        }
    }
    if (n < 0) { perror("read"); exit(1); }

    close(fd);
    if (out_len) *out_len = len;
    return buf;
}

static void parse_status(const char *pid, Status *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen status"); exit(1); }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name:", 5) == 0) {
            char *p = line + 5;
            while (*p == '\t' || *p == ' ') p++;
            size_t l = strlen(p);
            if (l && p[l - 1] == '\n') p[l - 1] = '\0';
            strncpy(st->name, p, sizeof(st->name) - 1);
        } else if (strncmp(line, "Threads:", 8) == 0) {
            st->threads = atoi(line + 8);
        }
    }
    fclose(f);
}

static void parse_maps(const char *pid, Status *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); exit(1); }

    char line[MAX_LINE];
    char prev[MAX_PATH] = "";

    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8] = "";
        char mpath[MAX_PATH] = "";

        /* addr perms offset dev inode [pathname] */
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255s",
                        &start, &end, perms, mpath);
        if (n < 3) continue; /* malformed line, skip */

        int is_rw = (perms[0] == 'r' && perms[1] == 'w');
        int keep = 0;

        if (is_rw) {
            if (strstr(mpath, "stack")) {
                keep = 1;
            } else if (st->name[0] && strstr(mpath, st->name)) {
                keep = 1;
            } else if (mpath[0] == '\0' && st->name[0] && strstr(prev, st->name)) {
                keep = 1;
            }
        }

        if (keep && st->region_count < MAX_REGIONS) {
            Region *r = &st->regions[st->region_count++];
            r->start = start;
            r->end = end;
            strncpy(r->perms, perms, sizeof(r->perms) - 1);
            strncpy(r->path, mpath, sizeof(r->path) - 1);
            r->content = NULL;
            r->size = 0;
        }

        strncpy(prev, mpath, sizeof(prev) - 1);
    }
    fclose(f);
}

static void read_regions(const char *pid, Status *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/mem", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open mem"); exit(1); }

    for (int i = 0; i < st->region_count; i++) {
        Region *r = &st->regions[i];
        size_t len = r->end - r->start;
        r->content = malloc(len);
        if (!r->content) { perror("malloc region"); exit(1); }

        ssize_t got = pread(fd, r->content, len, (off_t)r->start);
        if (got < 0) {
            fprintf(stderr, "pread failed for region %lx-%lx: %s\n",
                    r->start, r->end, strerror(errno));
            free(r->content);
            r->content = NULL;
            r->size = 0;
            continue;
        }
        r->size = (size_t)got;
        printf("%zd byte read.\n", got);
    }
    close(fd);
}

static void parse_cwd(const char *pid, Status *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/cwd", pid);

    ssize_t n = readlink(path, st->cwd, sizeof(st->cwd) - 1);
    if (n < 0) { perror("readlink cwd"); exit(1); }
    st->cwd[n] = '\0';
}

/* Minimal binary checkpoint format:
 *
 * header:
 *   u32 name_len, char name[name_len]
 *   u32 threads
 *   u32 cmdline_len, char cmdline[cmdline_len]
 *   u32 environ_len, char environ[environ_len]
 *   u32 cwd_len, char cwd[cwd_len]
 *   u32 region_count
 *   for each region:
 *     u64 start, u64 end
 *     u32 perms_len, char perms[perms_len]
 *     u32 path_len, char path[path_len]
 *
 * region bytes are written to region/<start>-<end>.bin separately
 */

static void write_u32(FILE *f, uint32_t v) { fwrite(&v, sizeof(v), 1, f); }
static void write_u64(FILE *f, uint64_t v) { fwrite(&v, sizeof(v), 1, f); }
static void write_blob(FILE *f, const char *data, uint32_t len) {
    write_u32(f, len);
    if (len) fwrite(data, 1, len, f);
}

static void save(Status *st) {
    FILE *f = fopen("checkpoint.bin", "wb");
    if (!f) { perror("fopen checkpoint.bin"); exit(1); }

    write_blob(f, st->name, (uint32_t)strlen(st->name));
    write_u32(f, (uint32_t)st->threads);
    write_blob(f, st->cmdline, (uint32_t)st->cmdline_len);
    write_blob(f, st->environ, (uint32_t)st->environ_len);
    write_blob(f, st->cwd, (uint32_t)strlen(st->cwd));
    write_u32(f, (uint32_t)st->region_count);

    for (int i = 0; i < st->region_count; i++) {
        Region *r = &st->regions[i];
        write_u64(f, r->start);
        write_u64(f, r->end);
        write_blob(f, r->perms, (uint32_t)strlen(r->perms));
        write_blob(f, r->path, (uint32_t)strlen(r->path));
    }
    fclose(f);

    mkdir("region", 0755);
    for (int i = 0; i < st->region_count; i++) {
        Region *r = &st->regions[i];
        if (!r->content) continue;

        char name[128];
        snprintf(name, sizeof(name), "region/%lx-%lx.bin", r->start, r->end);
        FILE *rf = fopen(name, "wb");
        if (!rf) { perror("fopen region file"); exit(1); }

        size_t n = fwrite(r->content, 1, r->size, rf);
        if (n != r->size) {
            fprintf(stderr, "short write on %s\n", name);
            exit(1);
        }
        fclose(rf);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }
    const char *pid = argv[1];

    Status st;
    memset(&st, 0, sizeof(st));

    parse_status(pid, &st);
    printf("name=%s threads=%d\n", st.name, st.threads);
    if (st.threads != 1) {
        fprintf(stderr, "must be single threaded\n");
        return 1;
    }

    parse_maps(pid, &st);
    printf("found %d regions\n", st.region_count);

    read_regions(pid, &st);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    st.cmdline = read_whole_file(path, &st.cmdline_len);

    snprintf(path, sizeof(path), "/proc/%s/environ", pid);
    st.environ = read_whole_file(path, &st.environ_len);

    parse_cwd(pid, &st);
    printf("cwd=%s\n", st.cwd);

    printf("saving\n");
    save(&st);

    free(st.cmdline);
    free(st.environ);
    for (int i = 0; i < st.region_count; i++) {
        free(st.regions[i].content);
    }

    return 0;
}