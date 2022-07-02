#include "../include/ft_strace.h"

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
                    syscalls[i].name
            );
        }
    }
    fprintf(stderr, "%s",
            "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(stderr, "100.00 %11.6f %11.0d %9d %9.0d total\n",
            d_tot_time, 0, tot_calls, tot_errors);
}