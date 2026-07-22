#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (descriptor >= 0) {
        (void)close(descriptor);
        fputs("network isolation failed: socket creation succeeded\n", stderr);
        return 1;
    }
    if (errno != EPERM && errno != EACCES) {
        perror("network isolation returned an unexpected error");
        return 1;
    }

    puts("network isolation verified: socket creation denied");
    return 0;
}
