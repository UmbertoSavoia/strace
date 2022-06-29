#include "../include/ft_strace.h"

#include "../include/errnotab.h"
#include "../include/sigtab.h"
#include "../include/syscalls_64.h"

int printed = 0;

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
