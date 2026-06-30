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
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <elf.h>

#define MAX_LINE 1024
#define MAX_PATH 256
#define MAX_REGIONS 256

typedef enum {
    REGION_DATA,
    REGION_HEAP,
    REGION_STACK,
    REGION_ANON,
} RegionKind;

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[8];
    char path[MAX_PATH];
    unsigned char *content;
    size_t size;
    RegionKind kind;
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
    char exe_path[MAX_PATH];
    struct user_regs_struct regs;
    int have_regs;
} Status;

static void must(long err, const char *state) {
    if (err == -1) {
        fprintf(stderr, "state=%s errno=%d: %s\n", state, errno, strerror(errno));
    }
}

static void attach_and_get_regs(pid_t pid, Status *st) {
    must(ptrace(PTRACE_ATTACH, pid, 0, 0), "ATTACH");

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "pid=%d did not stop as expected\n", pid);
        exit(1);
    }
    printf("pid=%d stopped\n", pid);

    struct iovec iov = {
        .iov_base = &st->regs,
        .iov_len = sizeof(st->regs),
    };
    long ret = ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    must(ret, "GETREGSET");
    st->have_regs = (ret != -1);

    if (st->have_regs) {
        printf("RIP = 0x%llx\n", (unsigned long long)st->regs.rip);
        printf("RSP = 0x%llx\n", (unsigned long long)st->regs.rsp);
        printf("RBP = 0x%llx\n", (unsigned long long)st->regs.rbp);
    }
}

static void detach(pid_t pid) {
    must(ptrace(PTRACE_DETACH, pid, NULL, NULL), "DETACH");
}

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

static void parse_exe(const char *pid, Status *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/exe", pid);

    ssize_t n = readlink(path, st->exe_path, sizeof(st->exe_path) - 1);
    if (n < 0) { perror("readlink exe"); exit(1); }
    st->exe_path[n] = '\0';
}

/* Classification rules (no hardcoded addresses):
 *
 *   Data:  pathname == executable, perms == "rw-p"
 *   Heap:  pathname == "", perms == "rw-p", and the immediately
 *          preceding mapping was the executable's rw-p (Data) segment
 *          -- the anonymous region right after Data is BSS/heap.
 *   Stack: pathname == "[stack]"
 *
 * Anything else writable+private that doesn't match is kept as a
 * generic anonymous region.
 */
static void parse_maps(const char *pid, Status *st) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen maps"); exit(1); }

    char line[MAX_LINE];
    int prev_was_data = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8] = "";
        char mpath[MAX_PATH] = "";

        /* addr perms offset dev inode [pathname] */
        int n = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %255s",
                        &start, &end, perms, mpath);
        if (n < 3) { prev_was_data = 0; continue; } /* malformed line, skip */

        int is_priv_rw = (strcmp(perms, "rw-p") == 0);
        int is_stack = (strcmp(mpath, "[stack]") == 0);
        int is_data = is_priv_rw && st->exe_path[0] && strcmp(mpath, st->exe_path) == 0;
        int is_heap = is_priv_rw && mpath[0] == '\0' && prev_was_data;

        RegionKind kind;
        int keep = 0;

        if (is_stack) {
            kind = REGION_STACK;
            keep = 1;
        } else if (is_data) {
            kind = REGION_DATA;
            keep = 1;
        } else if (is_heap) {
            kind = REGION_HEAP;
            keep = 1;
        } else if (is_priv_rw) {
            /* still rw-p and private but doesn't match a named rule --
             * keep as a generic anonymous/mapped region */
            kind = REGION_ANON;
            keep = 1;
        }

        if (keep && st->region_count < MAX_REGIONS) {
            Region *r = &st->regions[st->region_count++];
            r->start = start;
            r->end = end;
            strncpy(r->perms, perms, sizeof(r->perms) - 1);
            strncpy(r->path, mpath, sizeof(r->path) - 1);
            r->content = NULL;
            r->size = 0;
            r->kind = kind;
        }

        /* heap detection depends on the *immediately preceding* maps
         * line being the Data segment, not just any kept region */
        prev_was_data = is_data;
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
 *   u32 have_regs, [struct user_regs_struct regs] (raw, if have_regs)
 *   for each region:
 *     u64 start, u64 end
 *     u32 kind (0=data 1=heap 2=stack 3=anon)
 *     u32 perms_len, char perms[perms_len]
 *     u32 path_len, char path[path_len]
 *
 * region bytes are written separately to region/data.bin, region/heap.bin,
 * region/stack.bin, or region/anon-<start>-<end>.bin depending on kind
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

    write_u32(f, (uint32_t)st->have_regs);
    if (st->have_regs) {
        fwrite(&st->regs, sizeof(st->regs), 1, f);
    }

    for (int i = 0; i < st->region_count; i++) {
        Region *r = &st->regions[i];
        write_u64(f, r->start);
        write_u64(f, r->end);
        write_u32(f, (uint32_t)r->kind);
        write_blob(f, r->perms, (uint32_t)strlen(r->perms));
        write_blob(f, r->path, (uint32_t)strlen(r->path));
    }
    fclose(f);

    mkdir("region", 0755);
    int data_n = 0, heap_n = 0, stack_n = 0;
    for (int i = 0; i < st->region_count; i++) {
        Region *r = &st->regions[i];
        if (!r->content) continue;

        char name[160];
        switch (r->kind) {
        case REGION_DATA:
            data_n++;
            if (data_n == 1) snprintf(name, sizeof(name), "region/data.bin");
            else snprintf(name, sizeof(name), "region/data%d.bin", data_n);
            break;
        case REGION_HEAP:
            heap_n++;
            if (heap_n == 1) snprintf(name, sizeof(name), "region/heap.bin");
            else snprintf(name, sizeof(name), "region/heap%d.bin", heap_n);
            break;
        case REGION_STACK:
            stack_n++;
            if (stack_n == 1) snprintf(name, sizeof(name), "region/stack.bin");
            else snprintf(name, sizeof(name), "region/stack%d.bin", stack_n);
            break;
        case REGION_ANON:
        default:
            snprintf(name, sizeof(name), "region/anon-%lx-%lx.bin", r->start, r->end);
            break;
        }

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
    const char *pid_str = argv[1];
    pid_t pid = atoi(pid_str);
    if (pid <= 0) {
        fprintf(stderr, "invalid pid: %s\n", pid_str);
        return 1;
    }

    Status st;
    memset(&st, 0, sizeof(st));

    parse_status(pid_str, &st);
    printf("name=%s threads=%d\n", st.name, st.threads);
    if (st.threads != 1) {
        fprintf(stderr, "must be single threaded\n");
        return 1;
    }

    /* stop the tracee before snapshotting maps/mem/regs so nothing
     * mutates underneath us mid-checkpoint */
    attach_and_get_regs(pid, &st);

    parse_exe(pid_str, &st);
    parse_maps(pid_str, &st);
    printf("found %d regions\n", st.region_count);

    read_regions(pid_str, &st);

    detach(pid);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    st.cmdline = read_whole_file(path, &st.cmdline_len);

    snprintf(path, sizeof(path), "/proc/%s/environ", pid_str);
    st.environ = read_whole_file(path, &st.environ_len);

    parse_cwd(pid_str, &st);
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