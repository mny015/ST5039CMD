#include "logger.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static pthread_mutex_t logger_mutex = PTHREAD_MUTEX_INITIALIZER;

static void logger_write(FILE *stream, const char *level,
                         const char *format, va_list args)
{
    int lock_result = pthread_mutex_lock(&logger_mutex);

    if (lock_result != 0) {
        fprintf(stderr, "[sandbox][LOGGER] mutex lock failed: %s\n",
                strerror(lock_result));
        return;
    }

    fprintf(stream, "[sandbox][%s] ", level);
    vfprintf(stream, format, args);
    fputc('\n', stream);
    fflush(stream);

    lock_result = pthread_mutex_unlock(&logger_mutex);
    if (lock_result != 0) {
        fprintf(stderr, "[sandbox][LOGGER] mutex unlock failed: %s\n",
                strerror(lock_result));
    }
}

void logger_info(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    logger_write(stdout, "INFO", format, args);
    va_end(args);
}

void logger_warn(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    logger_write(stderr, "WARN", format, args);
    va_end(args);
}

void logger_error(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    logger_write(stderr, "ERROR", format, args);
    va_end(args);
}
