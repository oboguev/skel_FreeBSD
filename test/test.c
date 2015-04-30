#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/module.h>
#include <sys/syscall.h>

int
main(int argc, char **argv)
{
    int syscall_num, error, modid;
    struct module_stat mstat;
    const char* verb;

    modid = modfind("sys/mytest");
    if (modid < 0)
    {
        perror("unable to find module mytest");
        exit(modid);
    }
    mstat.version = sizeof mstat;
    if (0 != (error = modstat(modid, &mstat)))
    {
        perror("unable to get module status");
        exit(error);
    }
    syscall_num = mstat.data.intval;
    printf("syscall num: %d\n", syscall_num);

    verb = (argc <= 1) ? "" : argv[1];

    if (0 == strcmp(verb, "print") && argc == 3)
    {
        error = syscall(syscall_num, 0, 0, argv[2], 0, NULL);
        if (error)  perror("error");
    }
    else if (0 == strcmp(verb, "devtree") && argc == 2)
    {
        error = syscall(syscall_num, 10, 0, NULL, 0, NULL);
        if (error)  perror("error");
    }
    else if (0 == strcmp(verb, "panic") && argc == 2)
    {
        error = syscall(syscall_num, 100, 0, NULL, 0, NULL);
        if (error)  perror("error");
    }
    else
    {
        printf("usage: test print string\n");
        printf("       test panic\n");
        error = EINVAL;
    }

    return error;
}
