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
#include <errno.h>
#include <stdarg.h>

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

int    handle_sig(pid_t pid, siginfo_t *sig)
{
    if (sig->si_signo == SIGTRAP) {
        return 0;
    } else if (sig->si_signo == SIGCHLD) {
        fprintf(stderr,
                "--- SIGCHLD {si_signo=SIGCHLD, si_code=%s, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%ld, si_stime=%ld} ---\n",
                sigtab[sig->si_signo].code[sig->si_code], sig->si_pid, sig->si_uid, sig->si_status, sig->si_utime, sig->si_stime);
    } else if (sig->si_signo == SIGSEGV || sig->si_signo == SIGBUS) {
        fprintf(stderr,
                "--- %s {si_signo=%s, si_code=%s, si_addr=0x%p} ---\n",
                sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].code[sig->si_code], sig->si_addr);
        fprintf(stderr, "+++ killed by %s +++\n", sigtab[sig->si_signo].name);
        raise((sig->si_signo == SIGSEGV) ? SIGSEGV : SIGBUS);
    }else if (sig->si_signo == SIGCONT || sig->si_signo == SIGTSTP || sig->si_signo == SIGINT) {
        fprintf(stderr, "--- %s {si_signo=%s, si_code=%s} ---\n",
                sigtab[sig->si_signo].name, sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].code[sig->si_code < 0 ? -sig->si_code : sig->si_code]);
    } else {
        fprintf(stderr,
                "--- %s {si_signo=%s, si_code=%s, si_pid=%d, si_uid=%d} ---\n",
                sigtab[sig->si_signo].name, sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].code[sig->si_code < 0 ? -sig->si_code : sig->si_code],
                sig->si_pid, sig->si_uid);
        if (sig->si_signo == SIGWINCH) {
            ptrace(PTRACE_SYSCALL, pid, 0, sig->si_signo);
            return 1;
        }
    }
    return 0;
}

void    sigaddset_multi(sigset_t *sigmask, int tot_arg, ...)
{
    va_list ap;

    va_start(ap, tot_arg);
    for (int i = 0; i < tot_arg; ++i)
        sigaddset(sigmask, va_arg(ap, int));
    va_end(ap);
}

int     intercept_syscall(pid_t pid, int *_status, struct user_regs_struct *ret)
{
    siginfo_t siginfo;
    int status = 0;
    sigset_t sigmask;

    sigemptyset(&sigmask);
    sigprocmask(SIG_SETMASK, &sigmask, NULL);

    waitpid(pid, &status, 0);

    sigemptyset(&sigmask);
    sigaddset_multi(&sigmask, 5,
                    SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM);
    sigprocmask(SIG_BLOCK, &sigmask, NULL);

    *_status = status;
    if (WIFEXITED(status))
        return -1;
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
        if (siginfo.si_code == (SIGTRAP | 0x80)) {
            get_regs(pid, ret);
            return 0;
        } else {
            if (handle_sig(pid, &siginfo))
                return -2;
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

char    *make_printable_string(char *s, int nsyscall, int size)
{
/*
    char *p = malloc(size*3+1);
    char *_p = p;

    for (int i = 0; i < size; ++i, ++p) {
        if (!isprint(s[i])) {
            if (s[i] == '\n') {
                *p++ = '\\';
                *p++ = 'n';
                *p = 0;
                if (nsyscall == 0) {
                    p++;
                    *p = 0;
                    break;
                }
            } else if (s[i] == '\t') {
                *p++ = '\\'; *p = 't';
            } else if (s[i] == '\r') {
                *p++ = '\\'; *p = 'r';
            } else if (s[i] == '\v') {
                *p++ = '\\'; *p = 'v';
            } else if (s[i] == '\f') {
                *p++ = '\\'; *p = 'f';
            } else {
                p += snprintf( p, 12, "\\%o", s[i]);
                p--;
            }
        } else {
            *p = s[i];
        }
    }
    *p = 0;
    return _p;
    */
    size_t s_size = size*3+1;
    char *escaped = malloc(s_size);
    char *p = 0;
    char c[] = "\n\t\f\v\r";
    char sc[32][4] = {
            ['\n'] = "\\n",
            ['\t'] = "\\t",
            ['\f'] = "\\f",
            ['\v'] = "\\v",
            ['\r'] = "\\r",
    };
    int j = 0;
    int i = 0;
    for (i = 0; i < size; ++i) {
        if ((p = strchr(c, s[i])) && s[i] != 0) {
            snprintf(escaped + i + j, s_size-(i+j), "%s", sc[p[0]]);
            ++j;
        } else if (!isprint(s[i])) {
            j += snprintf( escaped+i+j, s_size-(i+j), "\\%hho", s[i]);
            j-=1;
        } else {
            snprintf(escaped+i+j, s_size-(i+j), "%c", s[i]);
        }
    }
    escaped[i+j] = 0;
    return escaped;
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
            break;
        }
    }
    return strdup(s);
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
        long tmp = 0;
        unsigned long long int _size = 0;

        if (nsyscall == 0) {
            struct user_regs_struct reg_post = {0};
            get_regs(pid, &reg_post);
            _size = reg_post.rax;
        } else {
            _size = num_to_reg(regs, num_param+1);
        }

        int size = (_size > 32) ? 32 : (int)_size;
        s = malloc((size*3) * sizeof(char));
        for (int i = 0; i < size; i += sizeof(long)) {
            tmp = ptrace(PTRACE_PEEKDATA, pid, addr + i);
            memcpy(s + i, &tmp, sizeof(long));
        }
        _s = make_printable_string(s, nsyscall, (int)size);
        printed += fprintf(stderr, "\"%s\"%s", _s, (_size > 32) ? " ..." : "");
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
    if (n == O_RDWR) {
        snprintf( s, 128, "%s", (str_flag[2]+1));
    } else {
        if ((n & 1) == O_RDONLY)
            j += snprintf( s, 128, "%s", (str_flag[0]+1));
        for (int i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
            if (n & flag[i])
                j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
        }
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

void    errno_solve(struct user_regs_struct post_regs)
{
    int e = -1 - post_regs.rax + 1;

    fprintf(stderr, "%s %s (%s)",
            (e > 500) ? "?" : "-1",
            (e > 530) ? "NULL" : errno_tab[e].name,
            (!strlen(errno_tab[e].desc)) ? strerror(e) : errno_tab[e].desc);
}

char     *resolve_path(char *arg)
{
    struct stat statbuf = {0};
    char buf[4096] = {0};
    char *s = getenv("PATH");

    if (!lstat(arg, &statbuf))
        return strdup(arg);
    if (!s) return 0;
    char *p = strtok(s, ":");
    while (p) {
        snprintf(buf, 4096, "%s/%s", p, arg);
        if (!lstat(buf, &statbuf))
            return strdup(buf);
        p = strtok(0, ":");
    }
    return 0;
}

int     main(int ac, char **av, char **envp)
{
    if (ac < 2)
        return 1;
    char *solved_path = resolve_path(av[1]);

    if (!solved_path)
        return 1;
    pid_t pid = fork();

    if (pid == 0) {
        av[1] = solved_path;
        execve(av[1], av+1, envp);
        exit(1);
    } else if (pid > 0) {
        free(solved_path);
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
                    solve[param](pid, pre_regs, i+1);
                    if (i != 5 && i < 6 && syscalls_64[pre_regs.orig_rax].params[i+1] != NOPAR)
                        printed += fprintf(stderr, ", ");
                }
                if (pre_regs.orig_rax != 0 && pre_regs.orig_rax != 5) {
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                    intercept_syscall(pid, &status, &post_regs);
                }
                fprintf(stderr, ")%*s= ", (printed <= 40) ? (40 - printed) : 0, " ");
                if ((long)post_regs.rax < 0)
                    errno_solve(post_regs);
                else
                    solve[syscalls_64[pre_regs.orig_rax].ret](pid, post_regs, 7);
                fprintf(stderr, "\n");
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
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
