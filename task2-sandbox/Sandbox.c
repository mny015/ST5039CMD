#include "logger.h"
#include "monitor.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    logger_info("sandbox controller starting");
    monitor_describe_target(argv[1]);
    logger_info("process control implementation pending");

    return EXIT_SUCCESS;
}
