#define _POSIX_C_SOURCE 200809L

#include "logger.h"
#include "monitor.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT_SECONDS 5u
#define MAXIMUM_TIMEOUT_SECONDS 86400u
#define MONITOR_POLL_MILLISECONDS 100u
#define SUPERVISOR_POLL_MILLISECONDS 50u
#define TERMINATION_GRACE_MILLISECONDS 1000u

extern char **environ;

typedef struct SandboxOptions {
    const char *target_path;
    char **target_argv;
    unsigned int timeout_seconds;
} SandboxOptions;

static void print_usage(const char *program_name)
{
    fprintf(stderr,
            "Usage: %s [--timeout SECONDS] <target-binary> [args...]\n",
            program_name);
}

static int parse_timeout(const char *value, unsigned int *timeout_seconds)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0u ||
        parsed > MAXIMUM_TIMEOUT_SECONDS) {
        return -1;
    }

    *timeout_seconds = (unsigned int)parsed;
    return 0;
}

static int parse_options(int argc, char **argv, SandboxOptions *options)
{
    int target_index = 1;

    options->timeout_seconds = DEFAULT_TIMEOUT_SECONDS;

    if (argc > 1 && strcmp(argv[1], "--timeout") == 0) {
        if (argc < 4 || parse_timeout(argv[2], &options->timeout_seconds) != 0) {
            fputs("Invalid timeout. Use an integer from 1 to 86400 seconds.\n",
                  stderr);
            return -1;
        }
        target_index = 3;
    }

    if (target_index >= argc || argv[target_index][0] == '\0') {
        return -1;
    }

    options->target_path = argv[target_index];
    options->target_argv = &argv[target_index];
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

static int wait_for_child(pid_t child_pid, int options, int *child_status)
{
    pid_t wait_result;

    do {
        wait_result = waitpid(child_pid, child_status, options);
    } while (wait_result < 0 && errno == EINTR);

    if (wait_result == child_pid) {
        return 1;
    }
    if (wait_result == 0) {
        return 0;
    }

    logger_error("waitpid(%ld) failed: %s", (long)child_pid, strerror(errno));
    return -1;
}

static int wait_during_grace_period(pid_t child_pid, int *child_status)
{
    unsigned int waited_milliseconds = 0u;

    while (waited_milliseconds < TERMINATION_GRACE_MILLISECONDS) {
        int wait_result = wait_for_child(child_pid, WNOHANG, child_status);

        if (wait_result != 0) {
            return wait_result;
        }
        if (sleep_milliseconds(SUPERVISOR_POLL_MILLISECONDS) != 0) {
            logger_error("grace-period sleep failed: %s", strerror(errno));
            return -1;
        }
        waited_milliseconds += SUPERVISOR_POLL_MILLISECONDS;
    }

    return wait_for_child(child_pid, WNOHANG, child_status);
}

static int terminate_child(pid_t child_pid,
                           SandboxTerminationReason reason,
                           int *child_status)
{
    int wait_result;

    logger_warn("termination policy activated for PID %ld: %s",
                (long)child_pid, sandbox_termination_reason_name(reason));

    if (kill(child_pid, SIGTERM) != 0) {
        if (errno == ESRCH) {
            logger_info("PID %ld had already exited before SIGTERM",
                        (long)child_pid);
        } else {
            logger_error("SIGTERM delivery to PID %ld failed: %s",
                         (long)child_pid, strerror(errno));
        }
    } else {
        logger_warn("SIGTERM sent to PID %ld; waiting %u ms",
                    (long)child_pid, TERMINATION_GRACE_MILLISECONDS);
    }

    wait_result = wait_during_grace_period(child_pid, child_status);
    if (wait_result > 0) {
        logger_info("PID %ld exited during the SIGTERM grace period",
                    (long)child_pid);
        return 0;
    }

    if (wait_result < 0 && errno == ECHILD) {
        return -1;
    }

    logger_warn("PID %ld is still alive; sending SIGKILL", (long)child_pid);
    if (kill(child_pid, SIGKILL) != 0 && errno != ESRCH) {
        logger_error("SIGKILL delivery to PID %ld failed: %s",
                     (long)child_pid, strerror(errno));
        return -1;
    }

    wait_result = wait_for_child(child_pid, 0, child_status);
    return wait_result > 0 ? 0 : -1;
}

static int supervise_child(SandboxState *state, int *child_status,
                           SandboxTerminationReason *final_reason)
{
    for (;;) {
        SandboxStateSnapshot snapshot;
        int wait_result;

        wait_result = wait_for_child(state->child_pid, WNOHANG, child_status);
        if (wait_result > 0) {
            *final_reason = SANDBOX_TERMINATION_NONE;
            return 0;
        }
        if (wait_result < 0) {
            *final_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
            return terminate_child(state->child_pid, *final_reason,
                                   child_status);
        }

        if (sandbox_state_snapshot(state, &snapshot) != 0) {
            *final_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
            return terminate_child(state->child_pid, *final_reason,
                                   child_status);
        }

        if (snapshot.termination_requested) {
            *final_reason = snapshot.termination_reason;
            return terminate_child(snapshot.child_pid, snapshot.termination_reason,
                                   child_status);
        }

        if (sleep_milliseconds(SUPERVISOR_POLL_MILLISECONDS) != 0) {
            logger_error("supervisor sleep failed: %s", strerror(errno));
            *final_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
            return terminate_child(state->child_pid, *final_reason,
                                   child_status);
        }
    }
}

static int report_child_status(int child_status,
                               SandboxTerminationReason termination_reason)
{
    if (WIFEXITED(child_status)) {
        int exit_code = WEXITSTATUS(child_status);

        if (exit_code == 0 && termination_reason == SANDBOX_TERMINATION_NONE) {
            logger_info("final child status: normal exit (code=0)");
            return EXIT_SUCCESS;
        }

        logger_warn("final child status: abnormal exit (code=%d, reason=%s)",
                    exit_code,
                    sandbox_termination_reason_name(termination_reason));
        return EXIT_FAILURE;
    }

    if (WIFSIGNALED(child_status)) {
        logger_warn("final child status: signal termination "
                    "(signal=%d, reason=%s)",
                    WTERMSIG(child_status),
                    sandbox_termination_reason_name(termination_reason));
        return EXIT_FAILURE;
    }

    logger_error("final child status: unrecognized waitpid status 0x%x",
                 child_status);
    return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    SandboxOptions options;
    SandboxState state;
    TimeoutMonitorConfig monitor_config;
    SandboxTerminationReason final_reason = SANDBOX_TERMINATION_NONE;
    pthread_t monitor_thread;
    pid_t child_pid;
    int child_status = 0;
    int child_started = 0;
    int monitor_started = 0;
    int state_initialized = 0;
    int child_reaped = 0;
    int exit_code = EXIT_FAILURE;

    if (parse_options(argc, argv, &options) != 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (sandbox_state_init(&state) != 0) {
        return EXIT_FAILURE;
    }
    state_initialized = 1;

    logger_info("sandbox controller starting: target=%s timeout=%u seconds",
                options.target_path, options.timeout_seconds);

    child_pid = fork();
    if (child_pid < 0) {
        logger_error("fork() failed: %s", strerror(errno));
        goto cleanup;
    }

    if (child_pid == 0) {
        execve(options.target_path, options.target_argv, environ);
        dprintf(STDERR_FILENO, "sandbox child: execve(%s) failed: %s\n",
                options.target_path, strerror(errno));
        _exit(127);
    }

    child_started = 1;
    logger_info("parent supervising child PID %ld", (long)child_pid);
    if (sandbox_state_set_child(&state, child_pid) != 0) {
        final_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
        if (terminate_child(child_pid, final_reason, &child_status) == 0) {
            child_reaped = 1;
        }
        goto cleanup;
    }

    monitor_config.state = &state;
    monitor_config.timeout_seconds = options.timeout_seconds;
    monitor_config.poll_interval_milliseconds = MONITOR_POLL_MILLISECONDS;

    {
        int thread_result = pthread_create(&monitor_thread, NULL,
                                           timeout_monitor_thread,
                                           &monitor_config);
        if (thread_result != 0) {
            logger_error("timeout monitor thread creation failed: %s",
                         strerror(thread_result));
            (void)sandbox_state_request_termination(
                &state, SANDBOX_TERMINATION_MONITOR_ERROR);
        } else {
            monitor_started = 1;
        }
    }

    if (supervise_child(&state, &child_status, &final_reason) == 0) {
        child_reaped = 1;
    }

cleanup:
    if (child_started && !child_reaped) {
        if (final_reason == SANDBOX_TERMINATION_NONE) {
            final_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
        }
        logger_warn("performing final cleanup for unreaped PID %ld",
                    (long)child_pid);
        if (terminate_child(child_pid, final_reason, &child_status) == 0) {
            child_reaped = 1;
        } else {
            logger_error("unable to confirm that PID %ld was reaped",
                         (long)child_pid);
        }
    }

    if (child_started) {
        (void)sandbox_state_mark_child_exited(&state);
    }

    if (monitor_started) {
        int join_result = pthread_join(monitor_thread, NULL);

        if (join_result != 0) {
            logger_error("timeout monitor thread join failed: %s",
                         strerror(join_result));
        }
    }

    if (child_reaped) {
        exit_code = report_child_status(child_status, final_reason);
    }

    if (state_initialized) {
        (void)sandbox_state_destroy(&state);
    }
    return exit_code;
}
