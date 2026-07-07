#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

void logger_info(const char *format, ...)
{
    va_list args;

    fputs("[sandbox] ", stdout);

    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);

    fputc('\n', stdout);
}
