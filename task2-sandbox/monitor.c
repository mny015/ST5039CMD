#define _POSIX_C_SOURCE 200809L

#include "monitor.h"

#include "logger.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PROC_PATH_MAX 64u
#define PROC_STATUS_LINE_MAX 256u
#define PROC_STAT_LINE_MAX 4096u

typedef enum ProcReadResult {
    PROC_READ_ERROR = -1,
    PROC_READ_SUCCESS = 0,
    PROC_READ_PROCESS_GONE = 1
} ProcReadResult;

static int lock_state(SandboxState *state)
{
    int result = pthread_mutex_lock(&state->mutex);

    if (result != 0) {
        logger_error("shared-state mutex lock failed: %s", strerror(result));
        return -1;
    }
    return 0;
}

static int unlock_state(SandboxState *state)
{
    int result = pthread_mutex_unlock(&state->mutex);

    if (result != 0) {
        logger_error("shared-state mutex unlock failed: %s", strerror(result));
        return -1;
    }
    return 0;
}

static int sleep_milliseconds(unsigned int milliseconds)
{
    struct timespec delay;
    struct timespec remaining;

    delay.tv_sec = (time_t)(milliseconds / 1000u);
    delay.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;

    while (nanosleep(&delay, &remaining) != 0) {
        if (errno != EINTR) {
            return -1;
        }
        delay = remaining;
    }
    return 0;
}

static uint64_t elapsed_milliseconds(const struct timespec *start,
                                     const struct timespec *current)
{
    int64_t seconds = (int64_t)current->tv_sec - (int64_t)start->tv_sec;
    int64_t nanoseconds = (int64_t)current->tv_nsec - (int64_t)start->tv_nsec;

    return (uint64_t)(seconds * 1000LL + nanoseconds / 1000000LL);
}

static int build_proc_path(char *path, size_t path_size, pid_t child_pid,
                           const char *file_name)
{
    int length = snprintf(path, path_size, "/proc/%ld/%s",
                          (long)child_pid, file_name);

    return length >= 0 && (size_t)length < path_size ? 0 : -1;
}

static int process_gone_error(int error_code)
{
    return error_code == ENOENT || error_code == ESRCH;
}

static ProcReadResult read_memory_kilobytes(pid_t child_pid,
                                            unsigned long *memory_kilobytes,
                                            const char **metric_name)
{
    char path[PROC_PATH_MAX];
    char line[PROC_STATUS_LINE_MAX];
    unsigned long virtual_size = 0u;
    int found_virtual_size = 0;
    FILE *status_file;

    if (build_proc_path(path, sizeof(path), child_pid, "status") != 0) {
        logger_error("memory monitor could not build /proc status path");
        return PROC_READ_ERROR;
    }

    status_file = fopen(path, "r");
    if (status_file == NULL) {
        if (process_gone_error(errno)) {
            return PROC_READ_PROCESS_GONE;
        }
        logger_error("memory monitor could not open %s: %s",
                     path, strerror(errno));
        return PROC_READ_ERROR;
    }

    while (fgets(line, sizeof(line), status_file) != NULL) {
        unsigned long value;
        char unit[8];

        if (sscanf(line, "VmRSS: %lu %7s", &value, unit) == 2 &&
            strcmp(unit, "kB") == 0) {
            *memory_kilobytes = value;
            *metric_name = "VmRSS";
            if (fclose(status_file) != 0) {
                logger_error("memory monitor could not close %s: %s",
                             path, strerror(errno));
                return PROC_READ_ERROR;
            }
            return PROC_READ_SUCCESS;
        }

        if (sscanf(line, "VmSize: %lu %7s", &value, unit) == 2 &&
            strcmp(unit, "kB") == 0) {
            virtual_size = value;
            found_virtual_size = 1;
        }
    }

    if (ferror(status_file)) {
        logger_error("memory monitor failed while reading %s: %s",
                     path, strerror(errno));
        fclose(status_file);
        return PROC_READ_ERROR;
    }

    if (fclose(status_file) != 0) {
        logger_error("memory monitor could not close %s: %s",
                     path, strerror(errno));
        return PROC_READ_ERROR;
    }

    if (found_virtual_size) {
        *memory_kilobytes = virtual_size;
        *metric_name = "VmSize";
        return PROC_READ_SUCCESS;
    }

    logger_error("memory monitor found neither VmRSS nor VmSize in %s", path);
    return PROC_READ_ERROR;
}

static int parse_unsigned_token(const char *token,
                                unsigned long long *value)
{
    char *end = NULL;

    errno = 0;
    *value = strtoull(token, &end, 10);
    return errno == 0 && end != token && *end == '\0' ? 0 : -1;
}

static ProcReadResult read_cpu_ticks(pid_t child_pid,
                                     unsigned long long *user_ticks,
                                     unsigned long long *system_ticks)
{
    char path[PROC_PATH_MAX];
    char line[PROC_STAT_LINE_MAX];
    char *command_end;
    char *save_pointer = NULL;
    char *token;
    unsigned int field_number = 3u;
    int found_user_ticks = 0;
    int found_system_ticks = 0;
    FILE *stat_file;

    if (build_proc_path(path, sizeof(path), child_pid, "stat") != 0) {
        logger_error("CPU monitor could not build /proc stat path");
        return PROC_READ_ERROR;
    }

    stat_file = fopen(path, "r");
    if (stat_file == NULL) {
        if (process_gone_error(errno)) {
            return PROC_READ_PROCESS_GONE;
        }
        logger_error("CPU monitor could not open %s: %s",
                     path, strerror(errno));
        return PROC_READ_ERROR;
    }

    if (fgets(line, sizeof(line), stat_file) == NULL) {
        int read_error = errno;
        int reached_end = feof(stat_file);

        fclose(stat_file);
        if (reached_end || process_gone_error(read_error)) {
            return PROC_READ_PROCESS_GONE;
        }
        logger_error("CPU monitor could not read %s: %s",
                     path, strerror(read_error));
        return PROC_READ_ERROR;
    }

    if (fclose(stat_file) != 0) {
        logger_error("CPU monitor could not close %s: %s",
                     path, strerror(errno));
        return PROC_READ_ERROR;
    }

    command_end = strrchr(line, ')');
    if (command_end == NULL || command_end[1] != ' ') {
        logger_error("CPU monitor found malformed process stat for PID %ld",
                     (long)child_pid);
        return PROC_READ_ERROR;
    }

    token = strtok_r(command_end + 2, " \t\r\n", &save_pointer);
    while (token != NULL && field_number <= 15u) {
        if (field_number == 14u) {
            if (parse_unsigned_token(token, user_ticks) != 0) {
                logger_error("CPU monitor found invalid utime for PID %ld",
                             (long)child_pid);
                return PROC_READ_ERROR;
            }
            found_user_ticks = 1;
        } else if (field_number == 15u) {
            if (parse_unsigned_token(token, system_ticks) != 0) {
                logger_error("CPU monitor found invalid stime for PID %ld",
                             (long)child_pid);
                return PROC_READ_ERROR;
            }
            found_system_ticks = 1;
        }

        token = strtok_r(NULL, " \t\r\n", &save_pointer);
        field_number++;
    }

    if (!found_user_ticks || !found_system_ticks) {
        logger_error("CPU monitor could not parse utime/stime for PID %ld",
                     (long)child_pid);
        return PROC_READ_ERROR;
    }

    return PROC_READ_SUCCESS;
}

int sandbox_state_init(SandboxState *state)
{
    int result;

    memset(state, 0, sizeof(*state));
    state->child_pid = (pid_t)-1;
    state->termination_reason = SANDBOX_TERMINATION_NONE;

    result = pthread_mutex_init(&state->mutex, NULL);
    if (result != 0) {
        logger_error("shared-state mutex initialization failed: %s",
                     strerror(result));
        return -1;
    }
    return 0;
}

int sandbox_state_set_child(SandboxState *state, pid_t child_pid)
{
    if (child_pid <= 0 || lock_state(state) != 0) {
        return -1;
    }

    state->child_pid = child_pid;
    state->child_alive = 1;
    state->termination_requested = 0;
    state->termination_reason = SANDBOX_TERMINATION_NONE;
    return unlock_state(state);
}

int sandbox_state_snapshot(SandboxState *state,
                           SandboxStateSnapshot *snapshot)
{
    if (lock_state(state) != 0) {
        return -1;
    }

    snapshot->child_pid = state->child_pid;
    snapshot->child_alive = state->child_alive;
    snapshot->termination_requested = state->termination_requested;
    snapshot->termination_reason = state->termination_reason;
    return unlock_state(state);
}

int sandbox_state_request_termination(SandboxState *state,
                                      SandboxTerminationReason reason)
{
    int request_created = 0;

    if (reason == SANDBOX_TERMINATION_NONE || lock_state(state) != 0) {
        return -1;
    }

    if (state->child_alive && !state->termination_requested) {
        state->termination_requested = 1;
        state->termination_reason = reason;
        request_created = 1;
    }

    if (unlock_state(state) != 0) {
        return -1;
    }
    return request_created;
}

int sandbox_state_mark_child_exited(SandboxState *state)
{
    if (lock_state(state) != 0) {
        return -1;
    }

    state->child_alive = 0;
    return unlock_state(state);
}

int sandbox_state_destroy(SandboxState *state)
{
    int result = pthread_mutex_destroy(&state->mutex);

    if (result != 0) {
        logger_error("shared-state mutex destruction failed: %s",
                     strerror(result));
        return -1;
    }
    return 0;
}

const char *sandbox_termination_reason_name(SandboxTerminationReason reason)
{
    switch (reason) {
    case SANDBOX_TERMINATION_NONE:
        return "none";
    case SANDBOX_TERMINATION_TIMEOUT:
        return "timeout exceeded";
    case SANDBOX_TERMINATION_MEMORY_LIMIT:
        return "memory limit exceeded";
    case SANDBOX_TERMINATION_MONITOR_ERROR:
        return "monitor error";
    case SANDBOX_TERMINATION_SUPERVISOR_ERROR:
        return "supervisor error";
    default:
        return "unknown reason";
    }
}

void *timeout_monitor_thread(void *argument)
{
    TimeoutMonitorConfig *config = (TimeoutMonitorConfig *)argument;
    struct timespec start;
    const uint64_t timeout_milliseconds =
        (uint64_t)config->timeout_seconds * 1000u;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        logger_error("timeout monitor could not read monotonic clock: %s",
                     strerror(errno));
        (void)sandbox_state_request_termination(
            config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
        return NULL;
    }

    logger_info("timeout monitor started: limit=%u seconds",
                config->timeout_seconds);

    for (;;) {
        SandboxStateSnapshot snapshot;
        struct timespec current;
        int request_result;

        if (sandbox_state_snapshot(config->state, &snapshot) != 0) {
            return NULL;
        }
        if (!snapshot.child_alive || snapshot.termination_requested) {
            return NULL;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
            logger_error("timeout monitor could not update monotonic clock: %s",
                         strerror(errno));
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }

        if (elapsed_milliseconds(&start, &current) >= timeout_milliseconds) {
            request_result = sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_TIMEOUT);
            if (request_result > 0) {
                logger_warn("timeout exceeded after %u seconds; "
                            "termination requested for PID %ld",
                            config->timeout_seconds, (long)snapshot.child_pid);
            }
            return NULL;
        }

        if (sleep_milliseconds(config->poll_interval_milliseconds) != 0) {
            logger_error("timeout monitor sleep failed: %s", strerror(errno));
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }
    }
}

void *memory_monitor_thread(void *argument)
{
    MemoryMonitorConfig *config = (MemoryMonitorConfig *)argument;
    unsigned long last_logged_memory = ULONG_MAX;

    logger_info("memory monitor started: limit=%lu kB",
                config->memory_limit_kilobytes);

    for (;;) {
        SandboxStateSnapshot snapshot;
        unsigned long memory_kilobytes;
        const char *metric_name = NULL;
        ProcReadResult read_result;

        if (sandbox_state_snapshot(config->state, &snapshot) != 0) {
            return NULL;
        }
        if (!snapshot.child_alive || snapshot.termination_requested) {
            return NULL;
        }

        read_result = read_memory_kilobytes(snapshot.child_pid,
                                            &memory_kilobytes,
                                            &metric_name);
        if (read_result == PROC_READ_PROCESS_GONE) {
            return NULL;
        }
        if (read_result == PROC_READ_ERROR) {
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }

        {
            unsigned long memory_change = 0u;

            if (last_logged_memory != ULONG_MAX) {
                memory_change = memory_kilobytes >= last_logged_memory
                                    ? memory_kilobytes - last_logged_memory
                                    : last_logged_memory - memory_kilobytes;
            }

            if (last_logged_memory == ULONG_MAX ||
                memory_kilobytes >= config->memory_limit_kilobytes ||
                memory_change >= 1024u) {
                logger_info("memory sample: PID %ld %s=%lu kB limit=%lu kB",
                            (long)snapshot.child_pid, metric_name,
                            memory_kilobytes,
                            config->memory_limit_kilobytes);
                last_logged_memory = memory_kilobytes;
            }
        }

        if (memory_kilobytes >= config->memory_limit_kilobytes) {
            int request_result = sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MEMORY_LIMIT);

            if (request_result > 0) {
                logger_warn("memory limit exceeded by PID %ld: "
                            "%s=%lu kB limit=%lu kB",
                            (long)snapshot.child_pid, metric_name,
                            memory_kilobytes,
                            config->memory_limit_kilobytes);
            }
            return NULL;
        }

        if (sleep_milliseconds(config->poll_interval_milliseconds) != 0) {
            logger_error("memory monitor sleep failed: %s", strerror(errno));
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }
    }
}

void *cpu_monitor_thread(void *argument)
{
    CpuMonitorConfig *config = (CpuMonitorConfig *)argument;
    unsigned long long previous_total_ticks = 0u;
    struct timespec previous_time;
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    int have_previous_sample = 0;

    if (ticks_per_second <= 0) {
        logger_error("CPU monitor could not determine clock ticks per second");
        (void)sandbox_state_request_termination(
            config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
        return NULL;
    }

    logger_info("CPU monitor started: clock_ticks_per_second=%ld",
                ticks_per_second);

    for (;;) {
        SandboxStateSnapshot snapshot;
        unsigned long long user_ticks;
        unsigned long long system_ticks;
        unsigned long long total_ticks;
        struct timespec current_time;
        ProcReadResult read_result;

        if (sandbox_state_snapshot(config->state, &snapshot) != 0) {
            return NULL;
        }
        if (!snapshot.child_alive || snapshot.termination_requested) {
            return NULL;
        }

        read_result = read_cpu_ticks(snapshot.child_pid,
                                     &user_ticks, &system_ticks);
        if (read_result == PROC_READ_PROCESS_GONE) {
            return NULL;
        }
        if (read_result == PROC_READ_ERROR ||
            clock_gettime(CLOCK_MONOTONIC, &current_time) != 0) {
            if (read_result != PROC_READ_ERROR) {
                logger_error("CPU monitor could not read monotonic clock: %s",
                             strerror(errno));
            }
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }

        total_ticks = user_ticks + system_ticks;
        if (have_previous_sample && total_ticks >= previous_total_ticks) {
            uint64_t wall_milliseconds =
                elapsed_milliseconds(&previous_time, &current_time);

            if (wall_milliseconds > 0u) {
                unsigned long long delta_ticks =
                    total_ticks - previous_total_ticks;
                double cpu_percent =
                    ((double)delta_ticks * 100000.0) /
                    ((double)ticks_per_second * (double)wall_milliseconds);

                logger_info("CPU sample: PID %ld usage=%.1f%% "
                            "delta_ticks=%llu utime=%llu stime=%llu",
                            (long)snapshot.child_pid, cpu_percent,
                            delta_ticks, user_ticks, system_ticks);
            }
        } else {
            logger_info("CPU baseline: PID %ld utime=%llu stime=%llu",
                        (long)snapshot.child_pid, user_ticks, system_ticks);
        }

        previous_total_ticks = total_ticks;
        previous_time = current_time;
        have_previous_sample = 1;

        if (sleep_milliseconds(config->poll_interval_milliseconds) != 0) {
            logger_error("CPU monitor sleep failed: %s", strerror(errno));
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }
    }
}
