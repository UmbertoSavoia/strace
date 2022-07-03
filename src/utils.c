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
    static union {
        struct user_regs_struct      x86_64_r;
        struct i386_user_regs_struct i386_r;
    } x86_regs_union;
    struct iovec pt_iov = {
            .iov_base = &x86_regs_union,
            .iov_len = sizeof(x86_regs_union),
    };
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov);
    if (pt_iov.iov_len == sizeof(struct user_regs_struct)) {
        memcpy(ret, &x86_regs_union.x86_64_r, sizeof(struct user_regs_struct));
    } else if (pt_iov.iov_len == sizeof(struct i386_user_regs_struct)) {
        ret->orig_rax = x86_regs_union.i386_r.orig_eax;
        ret->rax = x86_regs_union.i386_r.eax;
        ret->rbx = x86_regs_union.i386_r.ebx;
        ret->rcx = x86_regs_union.i386_r.ecx;
        ret->rdx = x86_regs_union.i386_r.edx;
        ret->rsi = x86_regs_union.i386_r.esi;
        ret->rdi = x86_regs_union.i386_r.edi;
        ret->rbp = x86_regs_union.i386_r.ebp;
        ret->rip = x86_regs_union.i386_r.eip;
    } else {
        return -1;
    }
    return 0;
}

unsigned long long int num_to_reg_64(struct user_regs_struct regs, int n)
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
        default:
            return 0;
    }
    return 0;
}

unsigned long long int num_to_reg_32(struct user_regs_struct regs, int n)
{
    switch (n) {
        case 1:
            return regs.rbx;
        case 2:
            return regs.rcx;
        case 3:
            return regs.rdx;
        case 4:
            return regs.rsi;
        case 5:
            return regs.rdi;
        case 6:
            return regs.rbp;
        case 7: // return of syscall
            return regs.rax;
        default:
            return 0;
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

double  to_double(struct timeval *t)
{
    return t->tv_sec + t->tv_usec / 1000000.0;
}

int     check_arch(const char *filename)
{
    int fd = 0;
    unsigned char ident[EI_NIDENT] = {0};
    unsigned char magic[] = {
            127, 'E', 'L', 'F'
    };

    if ((fd = open(filename, O_RDONLY)) < 0)
        return -1;
    if (read(fd, ident, sizeof(ident)) < 0)
        return -1;
    if (memcmp(&ident[EI_MAG0], magic, sizeof(magic)) != 0)
        return -1;
    syscalls = syscalls_64;
    num_to_reg = &num_to_reg_64;
    if (ident[EI_CLASS] == ELFCLASS32) {
        fstat_n = 197;
        read_n = 3;
        write_n = 4;
    } else if (ident[EI_CLASS] == ELFCLASS64) {
        fstat_n = 5;
        read_n = 0;
        write_n = 1;
    } else {
        return -1;
    }
    return ident[EI_CLASS];
}

void    switch_32_mode(pid_t pid)
{
    syscalls = syscalls_32;
    num_to_reg = num_to_reg_32;
    fprintf(stderr, "[ Process PID=%d runs in 32 bit mode. ]\n", pid);
}