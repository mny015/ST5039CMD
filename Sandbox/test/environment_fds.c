#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int descriptor;

    if (getenv("SECRET_TEST_TOKEN") != NULL) {
        fputs("environment isolation failed: inherited secret found\n",
              stderr);
        return 1;
    }

    for (descriptor = 3; descriptor < 256; descriptor++) {
        errno = 0;
        if (fcntl(descriptor, F_GETFD) != -1 || errno != EBADF) {
            fprintf(stderr,
                    "descriptor isolation failed: FD %d is still open\n",
                    descriptor);
            return 1;
        }
    }

    puts("environment and descriptor isolation verified");
    return 0;
}
