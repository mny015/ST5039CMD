#include "monitor.h"

#include "logger.h"

void monitor_describe_target(const char *path)
{
    logger_info("monitor target: %s", path);
}
