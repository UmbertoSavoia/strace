#include "../include/ft_strace.h"

void    uint_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    printed += fprintf(stderr, "%u", (unsigned int)num_to_reg(regs, num_param));
}

void    int_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    printed += fprintf(stderr, "%d", (int)num_to_reg(regs, num_param));
}

void    long_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    printed += fprintf(stderr, "%ld", (long)num_to_reg(regs, num_param));
}

void    hex_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    unsigned long long int n = num_to_reg(regs, num_param);

    if (!n)
        printed += fprintf(stderr, "%s", "0");
    else
        printed += fprintf(stderr, "0x%llx", n);
}

void    ptr_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    unsigned long long int n = num_to_reg(regs, num_param);

    if (!n)
        printed += fprintf(stderr, "%s", "NULL");
    else
        printed += fprintf(stderr, "0x%llx", n);
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
    int nsyscall = (int)regs.orig_rax;
    unsigned long long int addr = num_to_reg(regs, num_param);

    if (nsyscall != read_n && nsyscall != write_n) {
        s = get_string(pid, addr);
        printed += fprintf(stderr, "\"%s\"", s);
        free(s);
    } else {
        long tmp = 0;
        unsigned long long int _size = 0;

        if (nsyscall == read_n) {
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
        _s = make_printable_string(s, (int)size);
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

    for (size_t i = 0; i < sizeof(buf); i += sizeof(long)) {
        tmp = ptrace(PTRACE_PEEKDATA, pid, reg + i);
        b[i / sizeof(long)] = tmp;
    }
    printed += fprintf(stderr, "{st_mode=%u, st_size=%ld, ...}", buf.st_mode, buf.st_size);
}

void    noparam_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    (void)regs;
    (void)num_param;
    printed += fprintf(stderr, "?");
}

void    prot_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
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
    for (size_t i = 1; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    map_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
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
    for (size_t i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    o_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
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
        for (size_t i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
            if (n & flag[i])
                j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
        }
    }
    printed += fprintf(stderr, "%s", s);
}

void    r_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
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
    for (size_t i = 1; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n & flag[i])
            j += snprintf( s + j, 128, "%s", (s[0] == 0) ? (str_flag[i]+1) : str_flag[i]);
    }
    printed += fprintf(stderr, "%s", s);
}

void    at_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    unsigned long long int n = num_to_reg(regs, num_param);
    unsigned int flag[] = {
            AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_SYMLINK_FOLLOW
    };
    char *str_flag[] = {
            "AT_FDCWD", "AT_SYMLINK_NOFOLLOW", "AT_REMOVEDIR", "AT_SYMLINK_FOLLOW"
    };

    for (size_t i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
        if (n == flag[i]) {
            printed += fprintf(stderr, "%s", str_flag[i]);
            break ;
        }
    }
}

void    arch_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param)
{
    (void)pid;
    unsigned long long int n = num_to_reg(regs, num_param);
    unsigned int flag[] = {
            ARCH_SET_GS, ARCH_SET_FS, ARCH_GET_FS, ARCH_GET_GS,
            ARCH_GET_CPUID, ARCH_SET_CPUID
    };
    char *str_flag[] = {
            "ARCH_SET_GS", "ARCH_SET_FS", "ARCH_GET_FS", "ARCH_GET_GS",
            "ARCH_GET_CPUID", "ARCH_SET_CPUID"
    };

    for (size_t i = 0; i < sizeof(flag) / sizeof(flag[0]); ++i) {
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
