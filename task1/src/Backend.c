#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define PROC_STATUS_PATH "/proc/self/status"
#define PROC_STATUS_LINE_MAX 256u

static void log_startup_uids(FILE *out)
{
    uid_t real_uid = getuid();
    uid_t effective_uid = geteuid();

    fprintf(out, "[backend] getuid(): %lu\n", (unsigned long)real_uid);
    fprintf(out, "[backend] geteuid(): %lu\n", (unsigned long)effective_uid);
}

static int log_proc_status_uid_lines(FILE *out)
{
    FILE *status_file;
    char line[PROC_STATUS_LINE_MAX];
    int found_uid_line = 0;

    status_file = fopen(PROC_STATUS_PATH, "r");
    if (status_file == NULL) {
        fprintf(out, "[backend] unable to open %s: %s\n",
                PROC_STATUS_PATH, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), status_file) != NULL) {
        if (strncmp(line, "Uid:", 4u) == 0) {
            fprintf(out, "[backend] /proc/self/status %s", line);
            found_uid_line = 1;
        }
    }

    if (ferror(status_file)) {
        fprintf(out, "[backend] error reading %s: %s\n",
                PROC_STATUS_PATH, strerror(errno));
        fclose(status_file);
        return -1;
    }

    if (fclose(status_file) != 0) {
        fprintf(out, "[backend] error closing %s: %s\n",
                PROC_STATUS_PATH, strerror(errno));
        return -1;
    }

    if (!found_uid_line) {
        fprintf(out, "[backend] no Uid line found in %s\n", PROC_STATUS_PATH);
        return -1;
    }

    return 0;
}

int main(void)
{
    FILE *log = stdout;

    fputs("[backend] startup\n", log);
    log_startup_uids(log);
    (void)log_proc_status_uid_lines(log);

    return EXIT_SUCCESS;
}
