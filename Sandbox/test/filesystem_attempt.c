#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int access_was_denied(int descriptor, const char *operation)
{
    if (descriptor >= 0) {
        (void)close(descriptor);
        fprintf(stderr, "filesystem isolation failed: %s succeeded\n",
                operation);
        return 0;
    }
    if (errno != EACCES && errno != EPERM) {
        fprintf(stderr, "%s returned unexpected error %d\n", operation,
                errno);
        return 0;
    }
    return 1;
}

int main(void)
{
    int read_descriptor = open("/etc/passwd", O_RDONLY);
    int write_descriptor;

    if (!access_was_denied(read_descriptor, "host file read")) {
        return 1;
    }

    write_descriptor = open("/tmp/st5039cmd-sandbox-write-test",
                            O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!access_was_denied(write_descriptor, "host file write")) {
        return 1;
    }

    puts("filesystem isolation verified: host reads and writes denied");
    return 0;
}
