#include "../include/ft_strace.h"

#include "../include/errnotab.h"
#include "../include/sigtab.h"
#include "../include/syscalls_64.h"

unsigned char is_summary = 0;
int printed = 0;

int    handle_sig(pid_t pid, siginfo_t *sig)
{
    if (sig->si_signo == SIGTRAP) {
        return 0;
    } else if (sig->si_signo == SIGCHLD) {
        if (!is_summary) fprintf(stderr,
                "--- SIGCHLD {si_signo=SIGCHLD, si_code=%s, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%ld, si_stime=%ld} ---\n",
                sigtab[sig->si_signo].code[sig->si_code], sig->si_pid, sig->si_uid, sig->si_status, sig->si_utime, sig->si_stime);
    } else if (sig->si_signo == SIGSEGV || sig->si_signo == SIGBUS) {
        if (!is_summary) fprintf(stderr,
                "--- %s {si_signo=%s, si_code=%s, si_addr=0x%p} ---\n",
                sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].code[sig->si_code], sig->si_addr);
        if (!is_summary) fprintf(stderr, "+++ killed by %s +++\n", sigtab[sig->si_signo].name);
        raise((sig->si_signo == SIGSEGV) ? SIGSEGV : SIGBUS);
    }else if (sig->si_signo == SIGCONT || sig->si_signo == SIGTSTP || sig->si_signo == SIGINT) {
        if (!is_summary) fprintf(stderr, "--- %s {si_signo=%s, si_code=%s} ---\n",
                sigtab[sig->si_signo].name, sigtab[sig->si_signo].name,
                sigtab[sig->si_signo].code[sig->si_code < 0 ? -sig->si_code : sig->si_code]);
    } else {
        if (!is_summary) fprintf(stderr,
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

int     intercept_syscall(pid_t pid, int *_status, struct user_regs_struct *ret, struct timeval *t)
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
            gettimeofday(t, 0);
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

void    handler_syscall_params(pid_t pid, struct user_regs_struct *pre_regs, struct user_regs_struct *post_regs,
                               f_solve *solve, int *status, struct timeval *t)
{
    if (!is_summary)
        printed += fprintf(stderr, "%s(", syscalls_64[pre_regs->orig_rax].name);
    for (int i = 0; i < 6; ++i) {
        if ((pre_regs->orig_rax == 0 || pre_regs->orig_rax == 5) && (i+1) == 2) {
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            intercept_syscall(pid, status, post_regs, t);
        }
        if (!is_summary) {
            unsigned char param = syscalls_64[pre_regs->orig_rax].params[i];
            if (param == NOPAR)
                break;
            solve[param](pid, *pre_regs, i+1);
            if (i != 5 && i < 6 && syscalls_64[pre_regs->orig_rax].params[i+1] != NOPAR)
                printed += fprintf(stderr, ", ");
        }
    }
}

void    handler_syscall_return(pid_t pid, struct user_regs_struct *pre_regs, struct user_regs_struct *post_regs,
                               f_solve *solve, int *status, struct timeval *t)
{
    if (pre_regs->orig_rax != 0 && pre_regs->orig_rax != 5) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        intercept_syscall(pid, status, post_regs, t);
    }
    if (!is_summary) {
        fprintf(stderr, ")%*s= ", (printed <= 40) ? (40 - printed) : 0, " ");
        if ((long)post_regs->rax < 0)
            errno_solve(*post_regs);
        else
            solve[(unsigned int)syscalls_64[pre_regs->orig_rax].ret](pid, *post_regs, 7);
        fprintf(stderr, "\n");
    }
}

void    update_summary(t_summary *summary, struct timeval *start, struct timeval *end,
                       struct user_regs_struct *pre, struct user_regs_struct *post)
{
    struct timeval temp = {0};

    timersub(end, start, &temp);
    timeradd(&summary[pre->orig_rax].t, &temp, &summary[pre->orig_rax].t);
    summary[pre->orig_rax].calls++;
    if ((long)post->rax < 0)
        summary[pre->orig_rax].errors++;
}

double to_double(struct timeval *t)
{
    return t->tv_sec + t->tv_usec / 1000000.0;
}

void    print_summary(t_summary *summary, int n)
{
    struct timeval tot_time = {0};
    int tot_calls = 0;
    int tot_errors = 0;
    double d_tot_time = 0;

    for (int i = 0; i < n; ++i) {
        if (summary[i].calls != 0) {
            timeradd(&tot_time, &summary[i].t, &tot_time);
            tot_calls += summary[i].calls;
            tot_errors += summary[i].errors;
        }
    }
    d_tot_time = to_double(&tot_time);

    fprintf(stderr, "%s%s",
            "% time     seconds  usecs/call     calls    errors syscall\n",
            "------ ----------- ----------- --------- --------- ----------------\n");
    for (int i = 0; i < n; ++i) {
        if (summary[i].calls != 0) {
            fprintf(stderr, "%6.2f %11.6f %11ld %9d %9.0d %s\n",
                        (to_double(&summary[i].t) / d_tot_time) * 100.0,
                        to_double(&summary[i].t),
                        (long)((long)(to_double(&summary[i].t) * 1000000)  / summary[i].calls),
                        summary[i].calls,
                        summary[i].errors,
                        syscalls_64[i].name
                    );
        }
    }
    fprintf(stderr, "%s",
            "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(stderr, "100.00 %11.6f %11.0d %9d %9.0d total\n",
            d_tot_time, 0, tot_calls, tot_errors);
}

int     ft_strace(pid_t pid)
{
    f_solve solve[16];
    t_summary summary[400] = {0};
    int status = 0;
    struct timeval start = {0}, end = {0};
    struct user_regs_struct pre_regs = {0}, post_regs = {0};

    init_solve(solve);
    ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_INTERRUPT, pid, 0, 0);
    ptrace(PTRACE_SYSCALL, pid, 0, 0);

    while (1) {
        if (!intercept_syscall(pid, &status, &pre_regs, &start)) {
            handler_syscall_params(pid, &pre_regs, &post_regs, solve, &status, &end);
            handler_syscall_return(pid, &pre_regs, &post_regs, solve, &status, &end);
            if (is_summary) update_summary(summary, &start, &end, &pre_regs, &post_regs);
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            printed = 0;
            if (WIFEXITED(status)) {
                if (!is_summary) {
                    fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
                } else {
                    memset(&summary[pre_regs.orig_rax], 0, sizeof(t_summary));
                    print_summary(summary, sizeof(summary) / sizeof(summary[0]));
                }
                return WEXITSTATUS(status);
            }
        }
    }
}

int     main(int ac, char **av, char **envp)
{
    if (ac < 2)
        return 1;
    char *solved_path = 0;

    is_summary = !memcmp(av[1], "-c", 2) ? 2 : 0;
    if (!(solved_path = resolve_path(av[!is_summary ? 1 : is_summary])))
        return 2;
    pid_t pid = fork();

    if (pid == 0) {
        unsigned char i = is_summary == 0 ? 1 : is_summary;
        av[i] = solved_path;
        execve(av[i], av+i, envp);
        exit(3);
    } else if (pid > 0) {
        free(solved_path);
        return ft_strace(pid);
    } else {
        return 4;
    }
}
