#define _GNU_SOURCE
#include<stdio.h>
#include <string.h>
#include <stdlib.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/wait.h>
#include <errno.h>
#include <sys/uio.h>
#include <elf.h>

void must(int err, char* state) {
    if (err == -1) {
    printf("state=%s errno=%d: %s\n", state, errno, strerror(errno));
  }
}

int main(int argc, char *argv[]) {
    char *pid = argv[1];
    if (strcmp(pid, "") == 0) {
        printf("must provide pid");
        return 1;
    }
    printf("PID = %s\n", pid);

    pid_t PID = atoi(pid);

    // must(ptrace(PTRACE_SEIZE, PID, 0, 0));
    // must(ptrace(PTRACE_INTERRUPT, PID));

    must(ptrace(PTRACE_ATTACH, PID, 0, 0), "ATTACH");

    int status;
    waitpid(PID,&status, 0);

    // if (WSTOPSIG(status)) {
    //     printf("PID=%d WSTOPSIG=%d\n", PID, WSTOPSIG(status));
    // }

    if (WIFSTOPPED(status)) {
        printf("PID=%d WIFSTOPPED=%d\n", PID, WIFSTOPPED(status));
    } else {
        return 1;
    }

    printf("PID=%d process stopped!!\n", PID);

    printf("about to GETREGS pid=%d\n", PID);
    struct user_regs_struct regs;
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };
    must(ptrace(PTRACE_GETREGSET, PID, (void *)NT_PRSTATUS, &iov), "GET REGISTER");

    printf("RIP = 0x%llx\n", (unsigned long long)regs.rip);
    printf("RSP = 0x%llx\n", (unsigned long long)regs.rsp);
    printf("RBP = 0x%llx\n", (unsigned long long)regs.rbp);
    printf("RAX = 0x%llx\n", (unsigned long long)regs.rax);
    printf("RBX = 0x%llx\n", (unsigned long long)regs.rbx);
    printf("RCX = 0x%llx\n", (unsigned long long)regs.rcx);
    printf("RDX = 0x%llx\n", (unsigned long long)regs.rdx);

    must(ptrace(PTRACE_DETACH, PID, NULL, NULL), "DETACH");

    FILE *f = fopen("regs.bin", "wb");
    if (!f) {
        perror("fopen");
        exit(1);
    }

    if (fwrite(&regs, sizeof(regs), 1, f) != 1) {
        perror("fwrite");
        exit(1);
    }

    fclose(f);

    return 0;
}