#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHILD_COUNT 4
#define CHILD_ALLOCATION_BYTES (8u * 1024u * 1024u)

int main(void)
{
    int index;

    if (setvbuf(stdout, NULL, _IOLBF, 0u) != 0) {
        return EXIT_FAILURE;
    }

    for (index = 0; index < CHILD_COUNT; index++) {
        pid_t child_pid = fork();

        if (child_pid < 0) {
            perror("memory_fork_hog: fork");
            return EXIT_FAILURE;
        }
        if (child_pid == 0) {
            size_t offset;
            unsigned char *memory = malloc(CHILD_ALLOCATION_BYTES);

            if (memory == NULL) {
                perror("memory_fork_hog: malloc");
                return EXIT_FAILURE;
            }
            for (offset = 0u; offset < CHILD_ALLOCATION_BYTES;
                 offset += 4096u) {
                memory[offset] = (unsigned char)index;
            }
            printf("memory_fork_hog: child PID=%ld allocated 8 MiB\n",
                   (long)getpid());
            for (;;) {
                pause();
            }
        }
    }

    while (wait(NULL) >= 0 || errno == EINTR) {
    }
    return EXIT_SUCCESS;
}
