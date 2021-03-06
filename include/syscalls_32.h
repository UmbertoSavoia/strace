#ifndef SYSCALLS_32_H
#define SYSCALLS_32_H

t_syscalls syscalls_32[] = {
        {"restart_syscall",			{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"exit",					{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, NOPAR},
        {"fork",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"read",					{ UINT, STR, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"write",					{ UINT, STR, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"open",					{ STR, INT, O_FLAG, NOPAR, NOPAR, NOPAR, }, INT},
        {"close",					{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"waitpid",					{ INT, PTR, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"creat",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"link",					{ STR, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"unlink",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"execve",					{ STR, STRTAB, VARS, NOPAR, NOPAR, NOPAR, }, INT},
        {"chdir",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"time",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mknod",					{ STR, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"chmod",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"lchown",					{ STR, LONG, LONG, NOPAR, NOPAR, NOPAR, }, INT},
        {"break",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"oldstat",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"lseek",					{ UINT, HEX, UINT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"getpid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mount",					{ STR, STR, STR, HEX, HEX, NOPAR, }, INT},
        {"umount",					{ STR, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"setuid",					{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"getuid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"stime",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ptrace",					{ HEX, HEX, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"alarm",					{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, UINT},
        {"oldfstat",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"pause",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"utime",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"stty",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"gtty",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"access",					{ STR, R_FLAG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"nice",					{ INT,	NOPAR,	NOPAR,	NOPAR,	NOPAR,	NOPAR,	}, INT},
        {"ftime",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sync",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"kill",					{ LONG, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"rename",					{ STR, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"mkdir",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"rmdir",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"dup",						{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"pipe",					{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"times",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, UINT},
        {"prof",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"brk",						{ PTR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, HEX},
        {"setgid",					{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"getgid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"signal",					{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"geteuid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"getegid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"acct",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"umount2",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"lock",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"ioctl",					{ UINT, UINT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"fcntl",					{ UINT, UINT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"mpx",						{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setpgid",					{ LONG, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ulimit",					{ INT,	LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"oldolduname",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"umask",					{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"chroot",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ustat",					{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"dup2",					{ UINT, UINT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"getppid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"getpgrp",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"setsid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sigaction",				{ INT, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"sgetmask",				{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"ssetmask",				{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"setreuid",				{ LONG, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"setregid",				{ LONG, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sigsuspend",				{ INT, INT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"sigpending",				{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sethostname",				{ STR, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"setrlimit",				{ UINT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"getrlimit",				{ UINT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"getrusage",				{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"gettimeofday",			{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"settimeofday",			{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"getgroups",				{ INT, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"setgroups",				{ INT, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"select",					{ INT, PTR, PTR, PTR, PTR, NOPAR, }, INT},
        {"symlink",					{ STR, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"oldlstat",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"readlink",				{ STR, STR, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"uselib",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"swapon",					{ STR, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"reboot",					{ INT, INT, UINT, HEX, NOPAR, NOPAR, }, INT},
        {"readdir",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, PTR},
        {"mmap",					{ PTR, INT, PROT, MAP, INT, HEX, }, HEX},
        {"munmap",					{ PTR, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"truncate",				{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ftruncate",				{ UINT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"fchmod",					{ UINT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"fchown",					{ UINT, LONG, LONG, NOPAR, NOPAR, NOPAR, }, INT},
        {"getpriority",				{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"setpriority",				{ INT, INT, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"profil",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"statfs",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"fstatfs",					{ UINT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ioperm",					{ HEX, HEX, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"socketcall",				{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"syslog",					{ INT, STR, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"setitimer",				{ INT, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"getitimer",				{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"stat",					{ STR, STATBUF, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"lstat",					{ STR, STATBUF, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"fstat",					{ UINT, STATBUF, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"olduname",				{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"iopl",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"vhangup",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"idle",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"vm86old",					{ PTR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"wait4",					{ INT, PTR, INT, PTR, NOPAR, NOPAR, }, LONG},
        {"swapoff",					{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sysinfo",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ipc",						{ UINT, INT, HEX, HEX, HEX, HEX, }, INT},
        {"fsync",					{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sigreturn",				{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"clone",					{ HEX, HEX, HEX, HEX, HEX, NOPAR, }, INT},
        {"setdomainname",			{ STR, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"uname",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"modify_ldt",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"adjtimex",				{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"mprotect",				{ HEX, LONG, PROT, NOPAR, NOPAR, NOPAR, }, INT},
        {"sigprocmask",				{ INT, PTR, PTR, LONG, NOPAR, NOPAR, }, INT},
        {"create_module",			{ HEX, HEX, HEX, HEX, HEX, HEX, }, HEX},
        {"init_module",				{ HEX, HEX, STR, NOPAR, NOPAR, NOPAR, }, INT},
        {"delete_module",			{ STR, UINT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"get_kernel_syms",			{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"quotactl",				{ UINT, STR, LONG, HEX, NOPAR, NOPAR, }, INT},
        {"getpgid",					{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fchdir",					{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"bdflush",					{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sysfs",					{ INT, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"personality",				{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"afs_syscall",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setfsuid",				{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"setfsgid",				{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"_llseek",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getdents",				{ UINT, HEX, UINT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"_newselect",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"flock",					{ UINT, UINT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"msync",					{ HEX, LONG, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"readv",					{ HEX, PTR, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"writev",					{ HEX, PTR, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"getsid",					{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fdatasync",				{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"_sysctl",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"mlock",					{ HEX, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"munlock",					{ HEX, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"mlockall",				{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"munlockall",				{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_setparam",			{ LONG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_getparam",			{ LONG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_setscheduler",		{ LONG, INT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_getscheduler",		{ LONG, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_yield",				{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_get_priority_max",	{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_get_priority_min",	{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_rr_get_interval",	{ LONG, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"nanosleep",				{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"mremap",					{ HEX, HEX, HEX, HEX, HEX, NOPAR, }, HEX},
        {"setresuid",				{ LONG, LONG, LONG, NOPAR, NOPAR, NOPAR, }, INT},
        {"getresuid",				{ LONG, LONG, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"vm86",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"query_module",			{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"poll",					{ PTR, UINT, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"nfsservctl",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"setresgid",				{ LONG, LONG, LONG, NOPAR, NOPAR, NOPAR, }, INT},
        {"getresgid",				{ LONG, LONG, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"prctl",					{ INT, HEX, HEX, HEX, HEX, NOPAR, }, INT},
        {"rt_sigreturn",			{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"rt_sigaction",			{ INT, PTR, PTR, LONG, NOPAR, NOPAR, }, INT},
        {"rt_sigprocmask",			{ INT, PTR, PTR, LONG, NOPAR, NOPAR, }, INT},
        {"rt_sigpending",			{ HEX, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"rt_sigtimedwait",			{ HEX, HEX, HEX, LONG, NOPAR, NOPAR, }, INT},
        {"rt_sigqueueinfo",			{ LONG, INT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"rt_sigsuspend",			{ HEX, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"pread64",					{ UINT, STR, LONG, HEX, NOPAR, NOPAR, }, LONG},
        {"pwrite64",				{ UINT, STR, LONG, HEX, NOPAR, NOPAR, }, LONG},
        {"chown",					{ STR, LONG, LONG, NOPAR, NOPAR, NOPAR, }, INT},
        {"getcwd",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"capget",					{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"capset",					{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sigaltstack",				{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sendfile",				{ INT, INT, HEX, LONG, NOPAR, NOPAR, }, LONG},
        {"getpmsg",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"putpmsg",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"vfork",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"ugetrlimit",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"mmap2",					{ PTR, INT, PROT, MAP, INT, HEX, }, PTR},
        {"truncate64",				{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"ftruncate64",				{ UINT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"stat64",					{ STR, STATBUF, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"lstat64",					{ STR, STATBUF, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"fstat64",					{ HEX, STATBUF, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"lchown32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getgid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"geteuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getegid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setreuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setregid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getgroups32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setgroups32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"fchown32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setresuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getresuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setresgid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"getresgid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"chown32",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setgid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setfsuid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"setfsgid32",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"pivot_root",				{ STR, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"mincore",					{ HEX, LONG, STR, NOPAR, NOPAR, NOPAR, }, INT},
        {"madvise",					{ HEX, LONG, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"getdents64",				{ UINT, HEX, UINT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fcntl64",					{ UINT, UINT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"not implemented",			{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"not implemented",			{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"gettid",					{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"readahead",				{ INT, HEX, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"setxattr",				{ STR, STR, HEX, LONG, INT, NOPAR, }, LONG},
        {"lsetxattr",				{ STR, STR, HEX, LONG, INT, NOPAR, }, LONG},
        {"fsetxattr",				{ INT, STR, HEX, LONG, INT, NOPAR, }, LONG},
        {"getxattr",				{ STR, STR, HEX, LONG, NOPAR, NOPAR, }, LONG},
        {"lgetxattr",				{ STR, STR, HEX, LONG, NOPAR, NOPAR, }, LONG},
        {"fgetxattr",				{ INT, STR, HEX, LONG, NOPAR, NOPAR, }, LONG},
        {"listxattr",				{ STR, STR, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"llistxattr",				{ STR, STR, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"flistxattr",				{ INT, STR, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"removexattr",				{ STR, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"lremovexattr",			{ STR, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fremovexattr",			{ INT, STR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"tkill",					{ LONG, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"sendfile64",				{ INT, INT, HEX, LONG, NOPAR, NOPAR, }, LONG},
        {"futex",					{ HEX, INT, HEX, HEX, HEX, HEX, }, LONG},
        {"sched_setaffinity",		{ LONG, UINT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"sched_getaffinity",		{ LONG, UINT, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"set_thread_area",			{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"get_thread_area",			{ HEX, HEX, HEX, HEX, HEX, HEX, }, INT},
        {"io_setup",				{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"io_destroy",				{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"io_getevents",			{ HEX, HEX, HEX, HEX, HEX, NOPAR, }, INT},
        {"io_submit",				{ HEX, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"io_cancel",				{ HEX, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"fadvise64",				{ INT, HEX, LONG, INT, NOPAR, NOPAR, }, INT},
        {"not implemented",			{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"exit_group",				{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, NOPAR},
        {"lookup_dcookie",			{ HEX, STR, LONG, NOPAR, NOPAR, NOPAR, }, INT},
        {"epoll_create",			{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"epoll_ctl",				{ INT, INT, INT, HEX, NOPAR, NOPAR, }, INT},
        {"epoll_wait",				{ INT, HEX, INT, INT, NOPAR, NOPAR, }, INT},
        {"remap_file_pages",		{ HEX, HEX, HEX, HEX, HEX, NOPAR, }, INT},
        {"set_tid_address",			{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"timer_create",			{ LONG, HEX, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"timer_settime",			{ HEX, INT, HEX, HEX, NOPAR, NOPAR, }, INT},
        {"timer_gettime",			{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"timer_getoverrun",		{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"timer_delete",			{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"clock_settime",			{ LONG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"clock_gettime",			{ LONG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"clock_getres",			{ LONG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"clock_nanosleep",			{ LONG, INT, HEX, HEX, NOPAR, NOPAR, }, INT},
        {"statfs64",				{ STR, LONG, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"fstatfs64",				{ UINT, LONG, HEX, NOPAR, NOPAR, NOPAR, }, INT},
        {"tgkill",					{ LONG, LONG, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"utimes",					{ STR, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fadvise64_64",			{ INT, HEX, HEX, INT, NOPAR, NOPAR, }, INT},
        {"vserver",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"mbind",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"set_mempolicy",			{ INT, HEX, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"get_mempolicy",			{ INT, HEX, HEX, HEX, HEX, NOPAR, }, LONG},
        {"mq_open",					{ STR, INT, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"mq_unlink",				{ STR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mq_timedsend",			{ HEX, STR, LONG, UINT, HEX, NOPAR, }, LONG},
        {"mq_timedreceive",			{ HEX, STR, LONG, UINT, HEX, NOPAR, }, LONG},
        {"mq_notify",				{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mq_getsetattr",			{ HEX, HEX, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"kexec_load",				{ HEX, HEX, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"waitid",					{ INT, LONG, HEX, INT, HEX, NOPAR, }, LONG},
        {"not implemented",			{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"add_key",					{ STR, STR, HEX, LONG, HEX, NOPAR, }, LONG},
        {"request_key",				{ STR, STR, STR, HEX, NOPAR, NOPAR, }, LONG},
        {"keyctl",					{ INT, HEX, HEX, HEX, HEX, NOPAR, }, LONG},
        {"ioprio_set",				{ INT, INT, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"ioprio_get",				{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"inotify_init",			{ NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"inotify_add_watch",		{ INT, STR, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"inotify_rm_watch",		{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"migrate_pages",			{ LONG, HEX, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"openat",					{ AT_FLAG, STR, O_FLAG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mkdirat",					{ INT, STR, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mknodat",					{ INT, STR, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"fchownat",				{ INT, STR, LONG, LONG, INT, NOPAR, }, LONG},
        {"futimesat",				{ INT, STR, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fstatat64",				{ INT, STR, STATBUF, INT, NOPAR, NOPAR, }, LONG},
        {"unlinkat",				{ INT, STR, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"renameat",				{ INT, STR, INT, STR, NOPAR, NOPAR, }, LONG},
        {"linkat",					{ INT, STR, INT, STR, INT, NOPAR, }, LONG},
        {"symlinkat",				{ STR, INT, STR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"readlinkat",				{ INT, STR, STR, INT, NOPAR, NOPAR, }, LONG},
        {"fchmodat",				{ INT, STR, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"faccessat",				{ INT, STR, R_FLAG, INT, NOPAR, NOPAR, }, LONG},
        {"pselect6",				{ INT, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"ppoll",					{ HEX, UINT, HEX, HEX, LONG, NOPAR, }, LONG},
        {"unshare",					{ HEX, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"set_robust_list",			{ HEX, LONG, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"get_robust_list",			{ INT, HEX, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"splice",					{ INT, HEX, INT, HEX, LONG, UINT, }, LONG},
        {"sync_file_range",			{ INT, HEX, HEX, UINT, NOPAR, NOPAR, }, LONG},
        {"tee",						{ INT, INT, LONG, UINT, NOPAR, NOPAR, }, LONG},
        {"vmsplice",				{ INT, HEX, HEX, UINT, NOPAR, NOPAR, }, LONG},
        {"move_pages",				{ LONG, HEX, HEX, INT, INT, INT, }, LONG},
        {"getcpu",					{ HEX, HEX, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"epoll_pwait",				{ INT, HEX, INT, INT, HEX, LONG, }, LONG},
        {"utimensat",				{ INT, STR, HEX, INT, NOPAR, NOPAR, }, LONG},
        {"signalfd",				{ INT, HEX, LONG, NOPAR, NOPAR, NOPAR, }, LONG},
        {"timerfd_create",			{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"eventfd",					{ UINT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fallocate",				{ INT, INT, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"timerfd_settime",			{ INT, INT, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"timerfd_gettime",			{ INT, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"signalfd4",				{ INT, HEX, LONG, INT, NOPAR, NOPAR, }, LONG},
        {"eventfd2",				{ UINT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"epoll_create1",			{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"dup3",					{ UINT, UINT, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"pipe2",					{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"inotify_init1",			{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"preadv",					{ HEX, HEX, HEX, HEX, HEX, NOPAR, }, LONG},
        {"pwritev",					{ HEX, HEX, HEX, HEX, HEX, NOPAR, }, LONG},
        {"rt_tgsigqueueinfo",		{ LONG, LONG, INT, HEX, NOPAR, NOPAR, }, LONG},
        {"perf_event_open",			{ HEX, LONG, INT, INT, HEX, NOPAR, }, LONG},
        {"recvmmsg",				{ INT, HEX, UINT, HEX, HEX, NOPAR, }, LONG},
        {"fanotify_init",			{ UINT, UINT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"fanotify_mark",			{ INT, UINT, HEX, INT, STR, NOPAR, }, LONG},
        {"prlimit64",				{ LONG, UINT, HEX, HEX, NOPAR, NOPAR, }, LONG},
        {"name_to_handle_at",		{ INT, STR, HEX, INT, INT, NOPAR, }, LONG},
        {"open_by_handle_at",		{ INT, HEX, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"clock_adjtime",			{ LONG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"syncfs",					{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"sendmmsg",				{ INT, HEX, UINT, HEX, NOPAR, NOPAR, }, LONG},
        {"setns",					{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"process_vm_readv",		{ LONG, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"process_vm_writev",		{ LONG, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"kcmp",					{ LONG, LONG, INT, HEX, HEX, NOPAR, }, LONG},
        {"finit_module",			{ INT, STR, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"sched_setattr",			{ LONG, HEX, UINT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"sched_getattr",			{ LONG, HEX, UINT, UINT, NOPAR, NOPAR, }, LONG},
        {"renameat2",				{ INT, STR, INT, STR, UINT, NOPAR, }, LONG},
        {"seccomp",					{ UINT, UINT, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"getrandom",				{ STR, LONG, UINT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"memfd_create",			{ STR, UINT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"bpf",						{ INT, HEX, UINT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"execveat",				{ INT, STR, STRTAB, STRTAB, INT, NOPAR, }, LONG},
        {"socket",					{ INT, INT, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"socketpair",				{ INT, INT, INT, INT, NOPAR, NOPAR, }, INT},
        {"bind",					{ INT, HEX, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"connect",					{ INT, HEX, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"listen",					{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"accept4",					{ INT, HEX, INT, INT, NOPAR, NOPAR, }, LONG},
        {"getsockopt",				{ INT, INT, INT, STR, INT, NOPAR, }, INT},
        {"setsockopt",				{ INT, INT, INT, STR, INT, NOPAR, }, INT},
        {"getsockname",				{ INT, HEX, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"getpeername",				{ INT, HEX, INT, NOPAR, NOPAR, NOPAR, }, INT},
        {"sendto",					{ INT, HEX, LONG, HEX, HEX, INT, }, LONG},
        {"sendmsg",					{ INT, HEX, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"recvfrom",				{ INT, HEX, LONG, HEX, HEX, INT, }, LONG},
        {"recvmsg",					{ INT, HEX, HEX, NOPAR, NOPAR, NOPAR, }, LONG},
        {"shutdown",				{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        {"userfaultfd",				{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"membarrier",				{ INT, INT, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"mlock2",					{ HEX, LONG, INT, NOPAR, NOPAR, NOPAR, }, LONG},
        {"copy_file_range",			{ INT, HEX, INT, HEX, LONG, UINT, }, LONG},
        {"preadv2",					{ HEX, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"pwritev2",				{ HEX, HEX, HEX, HEX, HEX, HEX, }, LONG},
        {"pkey_mprotect",			{ HEX, LONG, HEX, INT, NOPAR, NOPAR, }, LONG},
        {"pkey_alloc",				{ HEX, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"pkey_free",				{ INT, NOPAR, NOPAR, NOPAR, NOPAR, NOPAR, }, LONG},
        {"statx",					{ INT, STR, HEX, HEX, HEX, NOPAR, }, LONG},
        {"arch_prctl",				{ ARCH_FLAG, HEX, NOPAR, NOPAR, NOPAR, NOPAR, }, INT},
        [407]{"clock_nanosleep_time64",			{ HEX, HEX, HEX, HEX, NOPAR, NOPAR, }, INT},
};

#endif