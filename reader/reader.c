#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/user.h>

/* mirrors the format written by save() in checkpoint.c:
 *
 *   u32 name_len, char name[name_len]
 *   u32 threads
 *   u32 cmdline_len, char cmdline[cmdline_len]
 *   u32 environ_len, char environ[environ_len]
 *   u32 cwd_len, char cwd[cwd_len]
 *   u32 region_count
 *   u32 have_regs, [struct user_regs_struct regs] (raw, if have_regs)
 *   for each region:
 *     u64 start, u64 end
 *     u32 perms_len, char perms[perms_len]
 *     u32 path_len, char path[path_len]
 */

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static uint32_t read_u32(FILE *f) {
    uint32_t v;
    if (fread(&v, sizeof(v), 1, f) != 1) die("read u32");
    return v;
}

static uint64_t read_u64(FILE *f) {
    uint64_t v;
    if (fread(&v, sizeof(v), 1, f) != 1) die("read u64");
    return v;
}

/* caller must free() the returned buffer */
static char *read_blob(FILE *f, uint32_t *out_len) {
    uint32_t len = read_u32(f);
    char *buf = malloc(len + 1);
    if (!buf) die("malloc blob");
    if (len) {
        if (fread(buf, 1, len, f) != len) die("read blob");
    }
    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

static void print_environ(const char *environ, uint32_t len) {
    /* environ is NUL-separated key=value pairs */
    const char *p = environ;
    const char *end = environ + len;
    while (p < end) {
        size_t l = strlen(p);
        if (l == 0) break;
        printf("    %s\n", p);
        p += l + 1;
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "checkpoint.bin";

    FILE *f = fopen(path, "rb");
    if (!f) die("fopen checkpoint.bin");

    uint32_t name_len, cmdline_len, environ_len, cwd_len;

    char *name = read_blob(f, &name_len);
    uint32_t threads = read_u32(f);
    char *cmdline = read_blob(f, &cmdline_len);
    char *environ = read_blob(f, &environ_len);
    char *cwd = read_blob(f, &cwd_len);
    uint32_t region_count = read_u32(f);

    uint32_t have_regs = read_u32(f);
    struct user_regs_struct regs;
    if (have_regs) {
        if (fread(&regs, sizeof(regs), 1, f) != 1) die("read regs");
    }

    printf("name:     %s\n", name);
    printf("threads:  %u\n", threads);
    printf("cmdline:  %.*s\n", (int)cmdline_len, cmdline);
    printf("cwd:      %s\n", cwd);
    printf("environ (%u bytes):\n", environ_len);
    print_environ(environ, environ_len);

    if (have_regs) {
        printf("regs:\n");
        printf("  RIP = 0x%llx\n", (unsigned long long)regs.rip);
        printf("  RSP = 0x%llx\n", (unsigned long long)regs.rsp);
        printf("  RBP = 0x%llx\n", (unsigned long long)regs.rbp);
        printf("  RAX = 0x%llx\n", (unsigned long long)regs.rax);
        printf("  RBX = 0x%llx\n", (unsigned long long)regs.rbx);
        printf("  RCX = 0x%llx\n", (unsigned long long)regs.rcx);
        printf("  RDX = 0x%llx\n", (unsigned long long)regs.rdx);
    } else {
        printf("regs:     (none captured)\n");
    }

    printf("regions:  %u\n", region_count);

    for (uint32_t i = 0; i < region_count; i++) {
        uint64_t start = read_u64(f);
        uint64_t end = read_u64(f);
        uint32_t perms_len, path_len;
        char *perms = read_blob(f, &perms_len);
        char *path_field = read_blob(f, &path_len);

        printf("  [%u] %lx-%lx %s %s\n", i,
               (unsigned long)start, (unsigned long)end,
               perms, path_field[0] ? path_field : "(anon)");

        /* corresponding bytes live in region/<start>-<end>.bin, written
         * separately by save() — open it here if you need the contents */
        char region_path[160];
        snprintf(region_path, sizeof(region_path), "region/%lx-%lx.bin",
                  (unsigned long)start, (unsigned long)end);
        FILE *rf = fopen(region_path, "rb");
        if (rf) {
            fseek(rf, 0, SEEK_END);
            long sz = ftell(rf);
            printf("      -> %s (%ld bytes on disk)\n", region_path, sz);
            fclose(rf);
        } else {
            printf("      -> %s (missing)\n", region_path);
        }

        free(perms);
        free(path_field);
    }

    fclose(f);
    free(name);
    free(cmdline);
    free(environ);
    free(cwd);

    return 0;
}