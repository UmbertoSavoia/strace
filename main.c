#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/user.h>
//#include <seccomp.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

#include "syscalls_64.h"

int printed = 0;

int     get_regs(pid_t pid, struct user_regs_struct *ret)
{
    struct user_regs_struct regs;

    struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };
    pt_iov.iov_base = &regs;
    pt_iov.iov_len = sizeof(regs);

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov) < 0)
        return -1;
    if (pt_iov.iov_len != sizeof(regs))
        return -1;
    memcpy(ret, &regs, sizeof(regs));
    return 0;
}

int     intercept_syscall(pid_t pid, int *_status, struct user_regs_struct *ret)
{
    siginfo_t siginfo;
    int status = 0;

    waitpid(pid, &status, 0);
    *_status = status;

    if (WIFEXITED(status))
        return -1;
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
        if (siginfo.si_code == SIGTRAP || siginfo.si_code == (SIGTRAP | 0x80)) {
            get_regs(pid, ret);
            //ptrace(PTRACE_SYSCALL, pid, 0, 0);
            return 0;
        }
    }
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    return -2;
}

unsigned long long int num_to_reg(struct user_regs_struct regs, int n)
{
    switch (n) {
        case 1:
            return regs.rdi;
        case 2:
            return regs.rsi;
        case 3:
            return regs.rdx;
        case 4:
            return regs.r10;
        case 5:
            return regs.r8;
        case 6:
            return regs.r9;
        case 7: // return of syscall
            return regs.rax;
    }
    return 0;
}

void    uint_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    printed += fprintf(stderr, "%u", (unsigned int)num_to_reg(regs, num_param));
}

void    int_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    printed += fprintf(stderr, "%d", (int)num_to_reg(regs, num_param));
}

void    long_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    printed += fprintf(stderr, "%ld", (long)num_to_reg(regs, num_param));
}

void    hex_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);

    if (!n)
        printed += fprintf(stderr, "%s", "0");
    else
        printed += fprintf(stderr, "0x%llx", n);
}

void    ptr_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);

    if (!n)
        printed += fprintf(stderr, "%s", "NULL");
    else
        printed += fprintf(stderr, "0x%llx", n);
}

char    *make_printable_string(char *s, int size)
{
    char *p = malloc(size*3);
    char *_p = p;

    for (int i = 0; i < size; ++i, ++s, ++p) {
        if (!isprint(*s)) {
            switch (*s) {
            case '\n':
                *p++ = '\\';
                *p = 'n';
                break;
            case '\t':
                *p++ = '\\';
                *p = 't';
                break;
            case '\r':
                *p++ = '\\';
                *p = 'r';
                break;
            case '\v':
                *p++ = '\\';
                *p = 'v';
                break;
            case '\f':
                *p++ = '\\';
                *p = 'v';
                break;
            default:
                p += snprintf( p, 12, "\\%o", *s);
                p--;
            }
        } else {
            *p = *s;
        }
    }
    return _p;
}

char    check_if_non_print(char *s)
{
    while (s && *s) {
        if (!isprint(*s))
            return 1;
        s++;
    }
    return 0;
}

char    *get_string(pid_t pid, unsigned long long int reg)
{
    char s[4096] = {0};
    long tmp = 0;
    int i = 0;
    char *p = 0;

    for (i = 0; i < 1024; i += sizeof(long)) {
        tmp = ptrace(PTRACE_PEEKDATA, pid, reg + i);
        memcpy(s + i, &tmp, sizeof(long));
        if (memchr(&tmp, 0, sizeof(long))) {
            //i = i + (p - (char *)&tmp);
            break;
        }
    }
    return /*check_if_non_print(s) ? make_printable_string(s, i) :*/ strdup(s);
}

void    strtab_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    char *s = 0;
    unsigned long long int addr = num_to_reg(regs, num_param);
    long addr_str = 0;

    printed += fprintf(stderr, "[");
    for (int i = 0; i >= 0; ++i) {
        if (!(addr_str = ptrace(PTRACE_PEEKDATA, pid, addr + (i * sizeof(char *)))))
            break;
        s = get_string(pid, addr_str);
        if (i > 0)
            printed += fprintf(stderr, ", ");
        printed += fprintf(stderr, "\"%s\"", s);
        free(s);
    }
    printed += fprintf(stderr, "]");
}

void    vars_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    char *s = 0;
    unsigned long long int addr = num_to_reg(regs, num_param);
    long addr_str = 0;
    long vars = 0;

    printed += fprintf(stderr, "0x%llx /* ", addr);
    for (int i = 0; i >= 0; ++i) {
        if (!(addr_str = ptrace(PTRACE_PEEKDATA, pid, addr + (i * sizeof(char *)))))
            break;
        s = get_string(pid, addr_str);
        vars++;
        free(s);
    }
    printed += fprintf(stderr, "%ld vars */", vars);
}

void    str_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    char *s = 0;
    char *_s = 0;
    unsigned long long int nsyscall = regs.orig_rax;
    unsigned long long int addr = num_to_reg(regs, num_param);

    if (nsyscall != 0 && nsyscall != 1) {
        s = get_string(pid, addr);
        printed += fprintf(stderr, "\"%s\"", s);
        free(s);
    } else {
        unsigned long long int size = num_to_reg(regs, num_param+1);
        long tmp = 0;

        size = (size > 32) ? 32 : size;
        s = malloc(size*3);
        for (int i = 0; i < size; i += sizeof(long)) {
            tmp = ptrace(PTRACE_PEEKDATA, pid, addr + i);
            memcpy(s + i, &tmp, sizeof(long));
        }
        _s = make_printable_string(s, (int)size);
        printed += fprintf(stderr, "\"%s\" ...", _s);
        free(s);
        free(_s);
    }
}

void    statbuf_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    struct stat buf = {0};
    long *b = (long *) &buf;
    unsigned long long int reg = num_to_reg(regs, num_param);
    long tmp = 0;

    for (int i = 0; i < sizeof(buf); i += sizeof(long)) {
        tmp = ptrace(PTRACE_PEEKDATA, pid, reg + i);
        b[i / sizeof(long)] = tmp;
    }
    printed += fprintf(stderr, "{st_mode=%u, st_size=%ld, ...}", buf.st_mode, buf.st_size);
}

void    noparam_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    printed += fprintf(stderr, "?");
}

void    prot_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);
    char s[128] = {0};
    int j = 0;
    unsigned int flag[] = {
            PROT_NONE,PROT_READ, PROT_WRITE,
            PROT_EXEC, PROT_GROWSDOWN, PROT_GROWSUP
    };
    char *str_flag[] = {
            "|PROT_NONE", "|PROT_READ", "|PROT_WRITE",
            "|PROT_EXEC", "|PROT_GROWSDOWN", "|PROT_GROWSUP"
    };

    if (n == PROT_NONE) {
        j += snprintf( s, 128, "%s", (str_flag[0]+1));
        printed += fprintf(stderr, "%s", s);
        return;
    }
    for (int i = 1; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    map_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);
    char s[128] = {0};
    int j = 0;
    unsigned int flag[] = {
            MAP_SHARED, MAP_PRIVATE, MAP_FIXED,
            MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE,
            MAP_STACK, MAP_HUGETLB,
    };
    char *str_flag[] = {
            "|MAP_SHARED", "|MAP_PRIVATE", "|MAP_FIXED",
            "|MAP_ANONYMOUS", "|MAP_DENYWRITE", "|MAP_EXECUTABLE",
            "|MAP_STACK", "|MAP_HUGETLB",
    };
    for (int i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    o_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);
    char s[128] = {0};
    int j = 0;
    unsigned int flag[] = {
            O_RDONLY, O_WRONLY, O_RDWR,
            O_ACCMODE, O_CLOEXEC
    };
    char *str_flag[] = {
            "|O_RDONLY", "|O_WRONLY", "|O_RDWR",
            "|O_ACCMODE", "|O_CLOEXEC"
    };
    if ((n & 1) == O_RDONLY)
        j += snprintf( s, 128, "%s", (str_flag[0]+1));
    for (int i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    r_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);
    char s[128] = {0};
    int j = 0;
    unsigned int flag[] = {
            F_OK, R_OK, W_OK, X_OK,
    };
    char *str_flag[] = {
            "|F_OK", "|R_OK", "|W_OK", "|X_OK",
    };

    if (n == F_OK) {
        j += snprintf( s, 128, "%s", (str_flag[0]+1));
        printed += fprintf(stderr, "%s", s);
        return;
    }
    for (int i = 1; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    at_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);
    unsigned int flag[] = {
            AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_SYMLINK_FOLLOW
    };
    char *str_flag[] = {
            "AT_FDCWD", "AT_SYMLINK_NOFOLLOW", "AT_REMOVEDIR", "AT_SYMLINK_FOLLOW"
    };

    for (int i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n == flag[i]) {
            printed += fprintf(stderr, "%s", str_flag[i]);
            break ;
        }
    }
}

void    arch_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    unsigned long long int n = num_to_reg(regs, num_param);
    unsigned int flag[] = {
        ARCH_SET_GS, ARCH_SET_FS, ARCH_GET_FS, ARCH_GET_GS,
        ARCH_GET_CPUID, ARCH_SET_CPUID
    };
    char *str_flag[] = {
            "ARCH_SET_GS", "ARCH_SET_FS", "ARCH_GET_FS", "ARCH_GET_GS",
            "ARCH_GET_CPUID", "ARCH_SET_CPUID"
    };

    for (int i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n == flag[i]) {
            printed += fprintf(stderr, "%s", str_flag[i]);
            break ;
        }
    }
}

int     main(int ac, char **av, char **envp)
{
    if (ac < 2) return 1;

    pid_t pid = fork();

    if (pid == 0) {
        execve(av[1], av+1, envp);
        puts("Error execve");
        exit(1);
    } else if (pid > 0) {
        typedef void (*f_solve)(pid_t pid, struct user_regs_struct regs, int num_param);
        f_solve solve[] = {
            noparam_solve,
            strtab_solve,
            str_solve,
            statbuf_solve,
            uint_solve,
            int_solve,
            long_solve,
            hex_solve,
            prot_flag_solve,
            map_flag_solve,
            o_flag_solve,
            at_flag_solve,
            vars_solve,
            r_flag_solve,
            ptr_solve,
            arch_flag_solve,
        };
        int status = 0;
        struct user_regs_struct pre_regs = {0}, post_regs = {0};

        ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD);
        ptrace(PTRACE_INTERRUPT, pid, 0, 0);
        ptrace(PTRACE_SYSCALL, pid, 0, 0);

        while (1) {
            if (!intercept_syscall(pid, &status, &pre_regs)) {
                printed += fprintf(stderr, "%s(", syscalls_64[pre_regs.orig_rax].name);
                for (int i = 0; i < 6; ++i) {
                    if ((pre_regs.orig_rax == 0 || pre_regs.orig_rax == 5)
                        && (i+1) == 2) {
                        ptrace(PTRACE_SYSCALL, pid, 0, 0);
                        intercept_syscall(pid, &status, &post_regs);
                    }
                    char param = syscalls_64[pre_regs.orig_rax].params[i];
                    if (param == NOPAR)
                        break;
                    if (i) printed += fprintf(stderr, ", ");
                    solve[param](pid, pre_regs, i+1);
                }
                if (pre_regs.orig_rax != 0 && pre_regs.orig_rax != 5) {
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                    intercept_syscall(pid, &status, &post_regs);
                }
                fprintf(stderr, ")%*s= ", (printed <= 40) ? (40 - printed) : 0, " ");
                solve[syscalls_64[pre_regs.orig_rax].ret](pid, post_regs, 7);
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                fprintf(stderr, "\n");
                printed = 0;
            } else if (WIFEXITED(status)) {
                fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
                break;
            }
        }
    } else {
        return 2;
    }
    return 0;
}
