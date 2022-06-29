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

extern int printed;
extern t_errno errno_tab[];
extern t_sigtab sigtab[32];
extern t_syscalls syscalls_64[];

typedef void (*f_solve)(pid_t pid, struct user_regs_struct regs, int num_param);

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
int                     get_regs(pid_t pid, struct user_regs_struct *ret);
unsigned long long int  num_to_reg(struct user_regs_struct regs, int n);
char                    *make_printable_string(char *s, int nsyscall, int size);
char                    *get_string(pid_t pid, unsigned long long int reg);
void                    sigaddset_multi(sigset_t *sigmask, int tot_arg, ...);

#endif