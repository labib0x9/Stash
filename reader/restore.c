#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* Mirrors the format written by save() in checkpoint.c — see checkpoint.c
 * for the authoritative layout. Restore proceeds in three phases:
 *   1. fork() + PTRACE_TRACEME + execve(self) -> get a stopped tracee
 *   2. for each region: inject an mmap() syscall via ptrace, then
 *      pwrite the saved bytes into it through /proc/<pid>/mem
 *   3. PTRACE_SETREGS with the saved regs, then detach
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

struct region {
    uint64_t start, end;
    char *perms;
    char *path;
};

/* ---- ptrace syscall injection ----
 *
 * To make the tracee execute mmap(), we:
 *   1. save its current regs
 *   2. point RIP at a `syscall` instruction we find in its own mapped
 *      text (we don't need to inject our own bytes — any existing
 *      `syscall` opcode in the tracee's address space works, since
 *      we're going to overwrite RIP afterward anyway)
 *   3. set RAX=sys_no, RDI..R9 = args
 *   4. single-step until we're back at our chosen address with the
 *      syscall completed (one PTRACE_SINGLESTEP is enough to execute
 *      the `syscall` instruction itself)
 *   5. read RAX for the return value
 *   6. restore the original regs
 *
 * Simplification: rather than scanning for a `syscall` opcode, we
 * write one (0x0F 0x05) over 2 bytes at the current RIP, run it, then
 * restore those bytes. This avoids needing to inject a fresh page.
 */

static long do_syscall_in_tracee(pid_t pid, struct user_regs_struct *saved,
                                  long sys_no, long a1, long a2, long a3,
                                  long a4, long a5, long a6) {
    struct user_regs_struct regs = *saved;

    uint64_t rip = saved->rip;
    long orig_word = ptrace(PTRACE_PEEKTEXT, pid, (void *)rip, NULL);
    if (orig_word == -1 && errno) die("PEEKTEXT");

    /* patch in 0x0F 0x05 (syscall) at RIP, keep rest of the word */
    long patched = (orig_word & ~0xFFFFL) | 0x050FL;
    if (ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)patched) == -1)
        die("POKETEXT patch");

    regs.rax = sys_no;
    regs.rdi = a1;
    regs.rsi = a2;
    regs.rdx = a3;
    regs.r10 = a4;
    regs.r8  = a5;
    regs.r9  = a6;
    regs.rip = rip;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) die("SETREGS inject");

    /* single-step over the syscall instruction itself */
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) die("SINGLESTEP");
    int status;
    if (waitpid(pid, &status, 0) == -1) die("waitpid singlestep");
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "tracee died during injected syscall (status=%d)\n", status);
        exit(1);
    }

    struct user_regs_struct after;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &after) == -1) die("GETREGS after");
    long ret = (long)after.rax;

    /* restore original bytes at RIP */
    if (ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)orig_word) == -1)
        die("POKETEXT restore");

    return ret;
}

static long inject_mmap(pid_t pid, struct user_regs_struct *saved,
                         uint64_t addr, uint64_t len, int prot) {
    /* mmap(addr, len, prot, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
    return do_syscall_in_tracee(pid, saved, SYS_mmap,
                                 (long)addr, (long)len, prot,
                                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                                 -1, 0);
}

static int prot_from_perms(const char *perms) {
    int prot = 0;
    if (strchr(perms, 'r')) prot |= PROT_READ;
    if (strchr(perms, 'w')) prot |= PROT_WRITE;
    if (strchr(perms, 'x')) prot |= PROT_EXEC;
    return prot;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "checkpoint.bin";

    FILE *f = fopen(path, "rb");
    if (!f) die("fopen checkpoint.bin");

    uint32_t name_len, cmdline_len, environ_len, cwd_len;
    char *name    = read_blob(f, &name_len);
    uint32_t threads = read_u32(f);
    char *cmdline = read_blob(f, &cmdline_len);
    char *environ = read_blob(f, &environ_len);
    char *cwd     = read_blob(f, &cwd_len);
    uint32_t region_count = read_u32(f);

    uint32_t have_regs = read_u32(f);
    struct user_regs_struct saved_regs;
    memset(&saved_regs, 0, sizeof(saved_regs));
    if (have_regs) {
        if (fread(&saved_regs, sizeof(saved_regs), 1, f) != 1) die("read regs");
    }

    struct region *regions = calloc(region_count, sizeof(*regions));
    if (!regions) die("calloc regions");

    for (uint32_t i = 0; i < region_count; i++) {
        regions[i].start = read_u64(f);
        regions[i].end   = read_u64(f);
        regions[i].perms = read_blob(f, NULL);
        regions[i].path  = read_blob(f, NULL);
    }
    fclose(f);

    (void)threads; (void)cmdline_len; (void)environ_len; (void)cwd_len;

    if (!have_regs) {
        fprintf(stderr, "checkpoint has no saved regs, cannot restore execution state\n");
        exit(1);
    }

    printf("restoring: %s (cwd=%s, %u regions)\n", name, cwd, region_count);

    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {
        /* child: become traceable, then re-exec itself as a parking spot.
         * argv[0] only — we don't care what this process "is", we're
         * about to overwrite its entire address space region by region. */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) die("PTRACE_TRACEME");
        if (chdir(cwd) == -1) { /* best effort */ }
        execl("/proc/self/exe", "restored", (char *)NULL);
        die("execl self");
    }

    /* parent */
    int status;
    if (waitpid(pid, &status, 0) == -1) die("waitpid initial");
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child did not stop after exec (status=%d)\n", status);
        exit(1);
    }
    /* stopped at SIGTRAP from execve */

    struct user_regs_struct parking_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &parking_regs) == -1) die("GETREGS parking");

    /* Phase 2: rebuild address space region by region.
     * We unmap nothing explicitly — MAP_FIXED on each target range
     * will clobber whatever the loader put there, including overlaps
     * with the parking binary's own mappings. Order doesn't generally
     * matter for disjoint ranges. */
    for (uint32_t i = 0; i < region_count; i++) {
        struct region *r = &regions[i];
        uint64_t len = r->end - r->start;
        int prot = prot_from_perms(r->perms);
        /* need write perm temporarily to pwrite contents even if the
         * final region is meant to be read-only/exec */
        int mmap_prot = prot | PROT_WRITE;

        long ret = inject_mmap(pid, &parking_regs, r->start, len, mmap_prot);
        if (ret != (long)r->start) {
            fprintf(stderr, "mmap region %u failed: requested 0x%lx got %ld (errno-ish)\n",
                    i, (unsigned long)r->start, ret);
            exit(1);
        }

        /* load saved bytes for this region, if present on disk */
        char region_path[160];
        snprintf(region_path, sizeof(region_path), "region/%lx-%lx.bin",
                  (unsigned long)r->start, (unsigned long)r->end);
        FILE *rf = fopen(region_path, "rb");
        if (rf) {
            char memp[64];
            snprintf(memp, sizeof(memp), "/proc/%d/mem", pid);
            int memfd = open(memp, O_RDWR);
            if (memfd < 0) die("open /proc/pid/mem");

            char buf[65536];
            size_t n;
            uint64_t off = r->start;
            while ((n = fread(buf, 1, sizeof(buf), rf)) > 0) {
                ssize_t w = pwrite(memfd, buf, n, (off_t)off);
                if (w != (ssize_t)n) die("pwrite region into tracee");
                off += n;
            }
            close(memfd);
            fclose(rf);
        } else {
            fprintf(stderr, "  [%u] no region file %s, leaving zero-filled\n", i, region_path);
        }

        /* if the region shouldn't be writable in the end, fix prot now
         * via injected mprotect */
        if (mmap_prot != prot) {
            long mp = do_syscall_in_tracee(pid, &parking_regs, SYS_mprotect,
                                            (long)r->start, (long)len, prot,
                                            0, 0, 0);
            if (mp != 0) {
                fprintf(stderr, "  [%u] mprotect fixup failed: %ld\n", i, mp);
            }
        }

        printf("  [%u] restored %lx-%lx %s\n", i,
               (unsigned long)r->start, (unsigned long)r->end, r->perms);
    }

    /* Phase 3: restore real registers and let it run */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) die("SETREGS final");

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) die("PTRACE_DETACH");

    printf("restored pid %d, resumed at rip=0x%llx\n",
           pid, (unsigned long long)saved_regs.rip);

    for (uint32_t i = 0; i < region_count; i++) {
        free(regions[i].perms);
        free(regions[i].path);
    }
    free(regions);
    free(name);
    free(cmdline);
    free(environ);
    free(cwd);

    return 0;
}