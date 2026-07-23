#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    pid_t descendant;

    if (setvbuf(stdout, NULL, _IOLBF, 0u) != 0) {
        return EXIT_FAILURE;
    }

    descendant = fork();
    if (descendant < 0) {
        perror("fork_escape: fork");
        return EXIT_FAILURE;
    }

    if (descendant > 0) {
        printf("fork_escape: original leader exiting; descendant PID=%ld\n",
               (long)descendant);
        return EXIT_SUCCESS;
    }

    if (setsid() < 0) {
        perror("fork_escape: setsid");
        return EXIT_FAILURE;
    }
    if (signal(SIGTERM, SIG_IGN) == SIG_ERR) {
        perror("fork_escape: signal");
        return EXIT_FAILURE;
    }

    printf("fork_escape: detached descendant PID=%ld PGID=%ld\n",
           (long)getpid(), (long)getpgrp());
    for (;;) {
        pause();
    }
}
