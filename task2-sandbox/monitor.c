#define _POSIX_C_SOURCE 200809L

#include "monitor.h"

#include "logger.h"
#include "process_tree.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

int sandbox_state_init(SandboxState *state)
{
    int result;

    memset(state, 0, sizeof(*state));
    state->supervisor_pid = getpid();
    state->child_pid = (pid_t)-1;
    state->child_process_group_id = (pid_t)-1;
    state->termination_reason = SANDBOX_TERMINATION_NONE;

    result = pthread_mutex_init(&state->mutex, NULL);
    if (result != 0) {
        logger_error("shared-state mutex initialization failed: %s",
                     strerror(result));
        return -1;
    }
    return 0;
}

int sandbox_state_set_workload(SandboxState *state, pid_t child_pid,
                               pid_t child_process_group_id)
{
    if (child_pid <= 0 || child_process_group_id <= 0 ||
        lock_state(state) != 0) {
        return -1;
    }

    state->child_pid = child_pid;
    state->child_process_group_id = child_process_group_id;
    state->leader_alive = 1;
    state->workload_alive = 1;
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

    snapshot->supervisor_pid = state->supervisor_pid;
    snapshot->child_pid = state->child_pid;
    snapshot->child_process_group_id = state->child_process_group_id;
    snapshot->leader_alive = state->leader_alive;
    snapshot->workload_alive = state->workload_alive;
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

    if (state->workload_alive && !state->termination_requested) {
        state->termination_requested = 1;
        state->termination_reason = reason;
        request_created = 1;
    }

    if (unlock_state(state) != 0) {
        return -1;
    }
    return request_created;
}

int sandbox_state_mark_leader_exited(SandboxState *state)
{
    if (lock_state(state) != 0) {
        return -1;
    }

    state->leader_alive = 0;
    return unlock_state(state);
}

int sandbox_state_mark_workload_exited(SandboxState *state)
{
    if (lock_state(state) != 0) {
        return -1;
    }

    state->leader_alive = 0;
    state->workload_alive = 0;
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
        if (!snapshot.workload_alive || snapshot.termination_requested) {
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
                logger_warn("timeout exceeded after %u seconds; termination "
                            "requested for process tree rooted at PID %ld",
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

    logger_info("memory monitor started: tree limit=%lu kB",
                config->memory_limit_kilobytes);

    for (;;) {
        SandboxStateSnapshot snapshot;
        ProcessTreeSample sample;
        unsigned long memory_change = 0u;

        if (sandbox_state_snapshot(config->state, &snapshot) != 0) {
            return NULL;
        }
        if (!snapshot.workload_alive || snapshot.termination_requested) {
            return NULL;
        }

        if (process_tree_sample(snapshot.supervisor_pid, snapshot.child_pid,
                                snapshot.leader_alive, &sample) != 0) {
            logger_error("memory monitor could not sample the process tree");
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }
        if (sample.process_count == 0u) {
            process_tree_sample_destroy(&sample);
            return NULL;
        }

        if (last_logged_memory != ULONG_MAX) {
            memory_change = sample.memory_kilobytes >= last_logged_memory
                                ? sample.memory_kilobytes - last_logged_memory
                                : last_logged_memory - sample.memory_kilobytes;
        }

        if (last_logged_memory == ULONG_MAX ||
            sample.memory_kilobytes >= config->memory_limit_kilobytes ||
            memory_change >= 1024u) {
            logger_info("memory sample: tree_processes=%zu %s=%lu kB "
                        "limit=%lu kB",
                        sample.process_count,
                        sample.used_virtual_memory_fallback
                            ? "aggregate VmRSS/VmSize"
                            : "aggregate VmRSS",
                        sample.memory_kilobytes,
                        config->memory_limit_kilobytes);
            last_logged_memory = sample.memory_kilobytes;
        }

        if (sample.memory_kilobytes >= config->memory_limit_kilobytes) {
            int request_result = sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MEMORY_LIMIT);

            if (request_result > 0) {
                logger_warn("memory limit exceeded by process tree: "
                            "processes=%zu memory=%lu kB limit=%lu kB",
                            sample.process_count, sample.memory_kilobytes,
                            config->memory_limit_kilobytes);
            }
            process_tree_sample_destroy(&sample);
            return NULL;
        }
        process_tree_sample_destroy(&sample);

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

    logger_info("CPU monitor started for process tree: "
                "clock_ticks_per_second=%ld", ticks_per_second);

    for (;;) {
        SandboxStateSnapshot snapshot;
        ProcessTreeSample sample;
        unsigned long long total_ticks;
        struct timespec current_time;

        if (sandbox_state_snapshot(config->state, &snapshot) != 0) {
            return NULL;
        }
        if (!snapshot.workload_alive || snapshot.termination_requested) {
            return NULL;
        }

        if (process_tree_sample(snapshot.supervisor_pid, snapshot.child_pid,
                                snapshot.leader_alive, &sample) != 0) {
            logger_error("CPU monitor could not sample the process tree");
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }
        if (sample.process_count == 0u) {
            process_tree_sample_destroy(&sample);
            return NULL;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &current_time) != 0) {
            logger_error("CPU monitor could not read monotonic clock: %s",
                         strerror(errno));
            process_tree_sample_destroy(&sample);
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }

        total_ticks = ULLONG_MAX - sample.user_ticks < sample.system_ticks
                          ? ULLONG_MAX
                          : sample.user_ticks + sample.system_ticks;
        if (have_previous_sample && total_ticks >= previous_total_ticks) {
            uint64_t wall_milliseconds =
                elapsed_milliseconds(&previous_time, &current_time);

            if (wall_milliseconds > 0u) {
                unsigned long long delta_ticks =
                    total_ticks - previous_total_ticks;
                double cpu_percent =
                    ((double)delta_ticks * 100000.0) /
                    ((double)ticks_per_second * (double)wall_milliseconds);

                logger_info("CPU sample: tree_processes=%zu usage=%.1f%% "
                            "delta_ticks=%llu utime=%llu stime=%llu",
                            sample.process_count, cpu_percent, delta_ticks,
                            sample.user_ticks, sample.system_ticks);
            }
        } else {
            logger_info("CPU baseline: tree_processes=%zu utime=%llu "
                        "stime=%llu",
                        sample.process_count, sample.user_ticks,
                        sample.system_ticks);
        }

        previous_total_ticks = total_ticks;
        previous_time = current_time;
        have_previous_sample = 1;
        process_tree_sample_destroy(&sample);

        if (sleep_milliseconds(config->poll_interval_milliseconds) != 0) {
            logger_error("CPU monitor sleep failed: %s", strerror(errno));
            (void)sandbox_state_request_termination(
                config->state, SANDBOX_TERMINATION_MONITOR_ERROR);
            return NULL;
        }
    }
}
