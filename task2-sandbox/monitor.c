#define _POSIX_C_SOURCE 200809L

#include "monitor.h"

#include "logger.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

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
    case SANDBOX_TERMINATION_MONITOR_ERROR:
        return "timeout monitor error";
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
