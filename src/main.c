#include "../include/ft_strace.h"

#include "../include/errnotab.h"
#include "../include/sigtab.h"
#include "../include/syscalls_64.h"
#include "../include/syscalls_32.h"

unsigned char is_summary = 0;
int printed = 0;
t_syscalls *syscalls = 0;
f_num_to_reg num_to_reg = 0;
int fstat_n = 0;
int read_n = 0;
int write_n = 0;

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

void    handler_syscall_params(pid_t pid, struct user_regs_struct *pre_regs, struct user_regs_struct *post_regs,
                               f_solve *solve, int *status, struct timeval *t)
{
    if (!is_summary)
        printed += fprintf(stderr, "%s(", syscalls[pre_regs->orig_rax].name);
    for (int i = 0; i < 6; ++i) {
        if (((int)pre_regs->orig_rax == read_n || (int)pre_regs->orig_rax == fstat_n) && (i+1) == 2) {
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            intercept_syscall(pid, status, post_regs, t);
        }
        if (!is_summary) {
            unsigned char param = syscalls[pre_regs->orig_rax].params[i];
            if (param == NOPAR)
                break;
            solve[param](pid, *pre_regs, i+1);
            if (i != 5 && i < 6 && syscalls[pre_regs->orig_rax].params[i+1] != NOPAR)
                printed += fprintf(stderr, ", ");
        }
    }
}

void    handler_syscall_return(pid_t pid, struct user_regs_struct *pre_regs, struct user_regs_struct *post_regs,
                               f_solve *solve, int *status, struct timeval *t)
{
    if ((int)pre_regs->orig_rax != read_n && (int)pre_regs->orig_rax != fstat_n) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        intercept_syscall(pid, status, post_regs, t);
    }
    if (!is_summary) {
        fprintf(stderr, ")%*s= ", (printed <= 40) ? (40 - printed) : 0, " ");
        if ((long)post_regs->rax < 0)
            errno_solve(*post_regs);
        else
            solve[(unsigned int)syscalls[pre_regs->orig_rax].ret](pid, *post_regs, 7);
        fprintf(stderr, "\n");
    }
}

void    handler_summary(int arch, t_summary *summary, t_summary *summary_switch, int size_summary)
{
    if (arch == ELFCLASS32) {
        syscalls = syscalls_64;
        print_summary(summary_switch, size_summary);
        fprintf(stderr, "%s\n", "System call usage summary for 32 bit mode:");
        syscalls = syscalls_32;
        print_summary(summary, size_summary);
    } else {
        print_summary(summary, size_summary);
    }
}

int     ft_strace(pid_t pid, int arch)
{
    f_solve solve[16];
    int status = 0;
    t_summary summary[400] = {0}, summary_switch[400] = {0};
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
            if (arch == ELFCLASS32 && syscalls == syscalls_64) {
                memcpy(&summary_switch[pre_regs.orig_rax], &summary[pre_regs.orig_rax], sizeof(t_summary));
                memset(&summary[pre_regs.orig_rax], 0, sizeof(t_summary));
                switch_32_mode(pid);
            }
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            printed = 0;
            if (WIFEXITED(status)) {
                if (!is_summary) {
                    fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
                } else {
                    memset(&summary[pre_regs.orig_rax], 0, sizeof(t_summary));
                    handler_summary(arch, summary, summary_switch, 400);
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
        int arch = 0;
        if ((arch = check_arch(solved_path)) < 0)
            return 4;
        free(solved_path);
        return ft_strace(pid, arch);
    } else {
        return 5;
    }
}
