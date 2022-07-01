#include "../include/ft_strace.h"

void    init_solve(f_solve *solve)
{
    solve[0] = &noparam_solve;
    solve[1] = &strtab_solve;
    solve[2] = &str_solve;
    solve[3] = &statbuf_solve;
    solve[4] = &uint_solve;
    solve[5] = &int_solve;
    solve[6] = &long_solve;
    solve[7] = &hex_solve;
    solve[8] = &prot_flag_solve;
    solve[9] = &map_flag_solve;
    solve[10] = &o_flag_solve;
    solve[11] = &at_flag_solve;
    solve[12] = &vars_solve;
    solve[13] = &r_flag_solve;
    solve[14] = &ptr_solve;
    solve[15] = &arch_flag_solve;
}

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

char    *make_printable_string(char *s, int size)
{
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
            snprintf(escaped + i + j, s_size-(i+j), "%s", sc[(unsigned char)p[0]]);
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

    for (int i = 0; i < 1024; i += sizeof(long)) {
        tmp = ptrace(PTRACE_PEEKDATA, pid, reg + i);
        memcpy(s + i, &tmp, sizeof(long));
        if (memchr(&tmp, 0, sizeof(long))) {
            break;
        }
    }
    return strdup(s);
}

void    sigaddset_multi(sigset_t *sigmask, int tot_arg, ...)
{
    va_list ap;

    va_start(ap, tot_arg);
    for (int i = 0; i < tot_arg; ++i)
        sigaddset(sigmask, va_arg(ap, int));
    va_end(ap);
}
