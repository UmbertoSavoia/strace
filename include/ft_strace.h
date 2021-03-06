#ifndef FT_STRACE_H
#define FT_STRACE_H

#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/user.h>
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
#include <sys/time.h>

enum types
{
    NOPAR,
    STRTAB,
    STR,
    STATBUF,
    UINT,
    INT,
    LONG,
    HEX,
    PROT,
    MAP,
    O_FLAG,
    AT_FLAG,
    VARS,
    R_FLAG,
    PTR,
    ARCH_FLAG,
};

typedef struct  s_syscalls
{
    char name[64];
    char params[6];
    char ret;
}               t_syscalls;

typedef struct  s_sigtab
{
    char name[32];
    char code[61][32];
}               t_sigtab;

typedef struct  s_errno
{
    char name[32];
    char desc[42];
}               t_errno;

typedef struct  s_summary
{
    struct timeval t;
    int calls;
    int errors;
}               t_summary;

struct i386_user_regs_struct {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint32_t xds;
    uint32_t xes;
    uint32_t xfs;
    uint32_t xgs;
    uint32_t orig_eax;
    uint32_t eip;
    uint32_t xcs;
    uint32_t eflags;
    uint32_t esp;
    uint32_t xss;
};

typedef void (*f_solve)(pid_t pid, struct user_regs_struct regs, int num_param);
typedef unsigned long long int (*f_num_to_reg)(struct user_regs_struct regs, int n);

extern int printed;
extern unsigned char is_summary;
extern t_errno errno_tab[];
extern t_sigtab sigtab[32];
extern t_syscalls syscalls_64[];
extern t_syscalls syscalls_32[];
extern t_syscalls *syscalls;
extern f_num_to_reg num_to_reg;
extern int fstat_n;
extern int read_n;
extern int write_n;

/**
 * solvers.c
 */
void    uint_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    int_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    long_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    hex_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    ptr_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    strtab_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    vars_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    str_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    statbuf_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    noparam_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    prot_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    map_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    o_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    r_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    at_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    arch_flag_solve(pid_t pid, struct user_regs_struct regs, int num_param);
void    errno_solve(struct user_regs_struct post_regs);

/**
 * utils.c
 */
void                    init_solve(f_solve *solve);
int                     get_regs(pid_t pid, struct user_regs_struct *ret);
unsigned long long int  num_to_reg_32(struct user_regs_struct regs, int n);
unsigned long long int  num_to_reg_64(struct user_regs_struct regs, int n);
char                    *make_printable_string(char *s, int size);
char                    *get_string(pid_t pid, unsigned long long int reg);
void                    sigaddset_multi(sigset_t *sigmask, int tot_arg, ...);
char                    *resolve_path(char *arg);
double                  to_double(struct timeval *t);
int                     check_arch(const char *filename);
void                    switch_32_mode(pid_t pid);
void                    _wait(pid_t pid, int *status);

/**
 * summary.c
 */
void    update_summary(t_summary *summary, struct timeval *start, struct timeval *end,
                        struct user_regs_struct *pre, struct user_regs_struct *post);
void    print_summary(t_summary *summary, int n);

#endif