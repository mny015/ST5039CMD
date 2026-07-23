#define _GNU_SOURCE

#include "logger.h"
#include "monitor.h"
#include "process_tree.h"
#include "security.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT_SECONDS 5u
#define MAXIMUM_TIMEOUT_SECONDS 86400u
#define MAXIMUM_MEMORY_LIMIT_KILOBYTES (4ul * 1024ul * 1024ul)
#define MONITOR_POLL_MILLISECONDS 100u
#define MEMORY_POLL_MILLISECONDS 25u
#define CPU_POLL_MILLISECONDS 250u
#define SUPERVISOR_POLL_MILLISECONDS 50u
#define TERMINATION_GRACE_MILLISECONDS 1000u
#define FORCE_KILL_WAIT_MILLISECONDS 5000u

static volatile sig_atomic_t operator_signal_number = 0;

typedef struct SandboxOptions {
    const char *target_path;
    char **target_argv;
    unsigned int timeout_seconds;
    unsigned long memory_limit_kilobytes;
} SandboxOptions;

typedef struct WorkloadStatus {
    int leader_status;
    int leader_status_available;
    unsigned long reaped_processes;
} WorkloadStatus;

static void handle_operator_signal(int signal_number)
{
    operator_signal_number = signal_number;
}

static int install_operator_signal_handlers(void)
{
    const int handled_signals[] = {SIGINT, SIGTERM, SIGHUP};
    struct sigaction action;
    size_t index;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_operator_signal;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }

    for (index = 0u;
         index < sizeof(handled_signals) / sizeof(handled_signals[0]);
         index++) {
        if (sigaction(handled_signals[index], &action, NULL) != 0) {
            return -1;
        }
    }
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int reset_child_signal_handlers(void)
{
    const int reset_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGPIPE};
    struct sigaction action;
    size_t index;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    for (index = 0u;
         index < sizeof(reset_signals) / sizeof(reset_signals[0]);
         index++) {
        if (sigaction(reset_signals[index], &action, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int wait_for_launch_permission(int descriptor)
{
    unsigned char permission;
    ssize_t bytes_read;

    do {
        bytes_read = read(descriptor, &permission, sizeof(permission));
    } while (bytes_read < 0 && errno == EINTR);

    if (bytes_read != (ssize_t)sizeof(permission) || permission != 1u) {
        errno = bytes_read < 0 ? errno : ECANCELED;
        return -1;
    }
    return 0;
}

static int release_child(int descriptor)
{
    const unsigned char permission = 1u;
    ssize_t bytes_written;

    do {
        bytes_written = write(descriptor, &permission, sizeof(permission));
    } while (bytes_written < 0 && errno == EINTR);

    return bytes_written == (ssize_t)sizeof(permission) ? 0 : -1;
}

static void print_usage(const char *program_name)
{
    fprintf(stderr,
            "Usage: %s [--timeout SECONDS] [--memory-kb KILOBYTES] "
            "<target-binary> [args...]\n",
            program_name);
}

static int parse_unsigned_limit(const char *value, unsigned long maximum,
                                unsigned long *parsed_value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0u ||
        parsed > maximum) {
        return -1;
    }

    *parsed_value = parsed;
    return 0;
}

static int parse_options(int argc, char **argv, SandboxOptions *options)
{
    int argument_index = 1;

    options->timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    options->memory_limit_kilobytes = 0u;

    while (argument_index < argc) {
        if (strcmp(argv[argument_index], "--timeout") == 0) {
            unsigned long timeout;

            if (argument_index + 1 >= argc ||
                parse_unsigned_limit(argv[argument_index + 1],
                                     MAXIMUM_TIMEOUT_SECONDS,
                                     &timeout) != 0) {
                fputs("Invalid timeout. Use an integer from 1 to 86400 "
                      "seconds.\n", stderr);
                return -1;
            }
            options->timeout_seconds = (unsigned int)timeout;
            argument_index += 2;
            continue;
        }

        if (strcmp(argv[argument_index], "--memory-kb") == 0) {
            if (argument_index + 1 >= argc ||
                parse_unsigned_limit(argv[argument_index + 1],
                                     MAXIMUM_MEMORY_LIMIT_KILOBYTES,
                                     &options->memory_limit_kilobytes) != 0) {
                fputs("Invalid memory limit. Use an integer from 1 to "
                      "4194304 kilobytes.\n", stderr);
                return -1;
            }
            argument_index += 2;
            continue;
        }

        if (strcmp(argv[argument_index], "--") == 0) {
            argument_index++;
            break;
        }

        if (argv[argument_index][0] == '-') {
            fprintf(stderr, "Unknown sandbox option: %s\n",
                    argv[argument_index]);
            return -1;
        }
        break;
    }

    if (argument_index >= argc || argv[argument_index][0] == '\0') {
        return -1;
    }

    options->target_path = argv[argument_index];
    options->target_argv = &argv[argument_index];
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

static int enable_child_subreaper(void)
{
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        logger_error("PR_SET_CHILD_SUBREAPER failed: %s", strerror(errno));
        return -1;
    }
    logger_info("controller registered as a Linux child subreaper");
    return 0;
}

static int reap_available_children(SandboxState *state,
                                   WorkloadStatus *workload_status)
{
    for (;;) {
        int status;
        pid_t reaped_pid = waitpid((pid_t)-1, &status, WNOHANG);

        if (reaped_pid > 0) {
            workload_status->reaped_processes++;
            if (reaped_pid == state->child_pid &&
                !workload_status->leader_status_available) {
                workload_status->leader_status = status;
                workload_status->leader_status_available = 1;
                (void)sandbox_state_mark_leader_exited(state);
                logger_info("reaped original workload leader PID %ld",
                            (long)reaped_pid);
            } else {
                logger_info("reaped descendant workload PID %ld",
                            (long)reaped_pid);
            }
            continue;
        }

        if (reaped_pid == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ECHILD) {
            return 0;
        }

        logger_error("waitpid(-1) failed: %s", strerror(errno));
        return -1;
    }
}

static int poll_workload(SandboxState *state,
                         const SandboxCgroup *cgroup,
                         WorkloadStatus *workload_status,
                         int *workload_alive)
{
    SandboxStateSnapshot snapshot;
    ProcessTreeSample sample;

    if (reap_available_children(state, workload_status) != 0 ||
        sandbox_state_snapshot(state, &snapshot) != 0) {
        return -1;
    }

    if (cgroup->active) {
        int populated = sandbox_cgroup_is_populated(cgroup);

        if (populated < 0) {
            logger_error("supervisor could not read cgroup membership: %s",
                         strerror(errno));
            return -1;
        }
        *workload_alive = populated;
        if (!*workload_alive) {
            (void)sandbox_state_mark_workload_exited(state);
        }
        return 0;
    }

    if (process_tree_sample(snapshot.supervisor_pid, snapshot.child_pid,
                            snapshot.leader_alive, &sample) != 0) {
        logger_error("supervisor could not sample the workload process tree");
        return -1;
    }

    *workload_alive = sample.process_count > 0u;
    process_tree_sample_destroy(&sample);
    if (!*workload_alive) {
        (void)sandbox_state_mark_workload_exited(state);
    }
    return 0;
}

static int signal_workload(SandboxState *state,
                           const SandboxCgroup *cgroup,
                           int signal_number)
{
    SandboxStateSnapshot snapshot;
    ProcessTreeSample sample;
    size_t index;
    size_t signalled_processes = 0u;
    int group_signalled = 0;
    int result = 0;

    if (sandbox_state_snapshot(state, &snapshot) != 0) {
        return -1;
    }
    memset(&sample, 0, sizeof(sample));

    if (signal_number == SIGKILL && cgroup->active) {
        if (sandbox_cgroup_kill(cgroup) == 0) {
            logger_warn("SIGKILL delivered atomically through cgroup.kill");
        } else {
            logger_error("cgroup.kill failed: %s", strerror(errno));
            result = -1;
        }
    }

    if (snapshot.child_process_group_id > 0) {
        if (kill(-snapshot.child_process_group_id, signal_number) == 0) {
            group_signalled = 1;
        } else if (errno != ESRCH) {
            logger_error("signal %d delivery to PGID %ld failed: %s",
                         signal_number,
                         (long)snapshot.child_process_group_id,
                         strerror(errno));
            result = -1;
        }
    }

    if (process_tree_sample(snapshot.supervisor_pid, snapshot.child_pid,
                            snapshot.leader_alive, &sample) != 0) {
        logger_error("could not collect process tree before signal %d",
                     signal_number);
        return -1;
    }

    for (index = 0u; index < sample.process_count; index++) {
        const ProcessTreeProcess *process = &sample.processes[index];

        if (process->pid <= 0 || process->pid == snapshot.supervisor_pid ||
            (group_signalled && process->process_group_id ==
                                    snapshot.child_process_group_id)) {
            continue;
        }

        if (kill(process->pid, signal_number) == 0) {
            signalled_processes++;
        } else if (errno != ESRCH) {
            logger_error("signal %d delivery to workload PID %ld failed: %s",
                         signal_number, (long)process->pid, strerror(errno));
            result = -1;
        }
    }

    logger_warn("signal %d delivered to workload tree: PGID=%ld "
                "discovered_processes=%zu individually_signalled=%zu",
                signal_number, (long)snapshot.child_process_group_id,
                sample.process_count, signalled_processes);
    process_tree_sample_destroy(&sample);
    return result;
}

static int wait_for_workload_exit(SandboxState *state,
                                  const SandboxCgroup *cgroup,
                                  WorkloadStatus *workload_status,
                                  unsigned int timeout_milliseconds,
                                  int repeat_sigkill)
{
    unsigned int waited_milliseconds = 0u;

    for (;;) {
        int workload_alive;

        if (poll_workload(state, cgroup, workload_status,
                          &workload_alive) != 0) {
            return -1;
        }
        if (!workload_alive) {
            return 0;
        }
        if (repeat_sigkill) {
            (void)signal_workload(state, cgroup, SIGKILL);
        }
        if (waited_milliseconds >= timeout_milliseconds) {
            return 1;
        }
        if (sleep_milliseconds(SUPERVISOR_POLL_MILLISECONDS) != 0) {
            logger_error("workload wait sleep failed: %s", strerror(errno));
            return -1;
        }
        waited_milliseconds += SUPERVISOR_POLL_MILLISECONDS;
    }
}

static int terminate_workload(SandboxState *state,
                              const SandboxCgroup *cgroup,
                              SandboxTerminationReason reason,
                              WorkloadStatus *workload_status)
{
    int wait_result;

    logger_warn("termination policy activated for workload tree: %s",
                sandbox_termination_reason_name(reason));
    (void)signal_workload(state, cgroup, SIGTERM);
    logger_warn("waiting %u ms for workload-wide SIGTERM shutdown",
                TERMINATION_GRACE_MILLISECONDS);

    wait_result = wait_for_workload_exit(state, cgroup, workload_status,
                                         TERMINATION_GRACE_MILLISECONDS, 0);
    if (wait_result == 0) {
        logger_info("entire workload exited during the SIGTERM grace period");
        return 0;
    }

    logger_warn("workload descendants remain; escalating tree to SIGKILL");
    (void)signal_workload(state, cgroup, SIGKILL);
    wait_result = wait_for_workload_exit(state, cgroup, workload_status,
                                         FORCE_KILL_WAIT_MILLISECONDS, 1);
    if (wait_result == 0) {
        logger_info("entire workload tree terminated and reaped");
        return 0;
    }

    logger_error("unable to confirm termination of the entire workload tree");
    return -1;
}

static int supervise_workload(SandboxState *state,
                              const SandboxCgroup *cgroup,
                              WorkloadStatus *workload_status,
                              SandboxTerminationReason *termination_reason)
{
    for (;;) {
        SandboxStateSnapshot snapshot;
        int workload_alive;

        if (operator_signal_number != 0) {
            logger_warn("controller received operator signal %d",
                        (int)operator_signal_number);
            *termination_reason = SANDBOX_TERMINATION_OPERATOR_SIGNAL;
            (void)sandbox_state_request_termination(state,
                                                     *termination_reason);
            return terminate_workload(state, cgroup, *termination_reason,
                                      workload_status);
        }

        if (poll_workload(state, cgroup, workload_status,
                          &workload_alive) != 0) {
            *termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
            return terminate_workload(state, cgroup, *termination_reason,
                                      workload_status);
        }
        if (!workload_alive) {
            *termination_reason = SANDBOX_TERMINATION_NONE;
            return 0;
        }

        if (sandbox_state_snapshot(state, &snapshot) != 0) {
            *termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
            return terminate_workload(state, cgroup, *termination_reason,
                                      workload_status);
        }
        if (snapshot.termination_requested) {
            *termination_reason = snapshot.termination_reason;
            return terminate_workload(state, cgroup,
                                      snapshot.termination_reason,
                                      workload_status);
        }

        if (sleep_milliseconds(SUPERVISOR_POLL_MILLISECONDS) != 0) {
            logger_error("supervisor sleep failed: %s", strerror(errno));
            *termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
            return terminate_workload(state, cgroup, *termination_reason,
                                      workload_status);
        }
    }
}

static int report_child_status(int child_status,
                               SandboxTerminationReason termination_reason)
{
    if (WIFEXITED(child_status)) {
        int exit_code = WEXITSTATUS(child_status);

        if (exit_code == 0 && termination_reason == SANDBOX_TERMINATION_NONE) {
            logger_info("final workload status: normal leader exit (code=0) "
                        "and no descendants remain");
            return EXIT_SUCCESS;
        }

        logger_warn("final workload status: leader exit code=%d reason=%s",
                    exit_code,
                    sandbox_termination_reason_name(termination_reason));
        return EXIT_FAILURE;
    }

    if (WIFSIGNALED(child_status)) {
        logger_warn("final workload status: leader signal=%d reason=%s",
                    WTERMSIG(child_status),
                    sandbox_termination_reason_name(termination_reason));
        return EXIT_FAILURE;
    }

    logger_error("final workload status: unrecognized waitpid status 0x%x",
                 child_status);
    return EXIT_FAILURE;
}

static void run_sandbox_child(const SandboxOptions *options,
                              int launch_read_descriptor,
                              int launch_write_descriptor,
                              pid_t expected_parent)
{
    (void)close(launch_write_descriptor);
    if (reset_child_signal_handlers() != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: could not reset signal handlers: %s\n",
                strerror(errno));
        _exit(127);
    }
    if (setpgid(0, 0) != 0) {
        dprintf(STDERR_FILENO, "sandbox child: setpgid() failed: %s\n",
                strerror(errno));
        _exit(127);
    }
    if (sandbox_child_set_parent_death_signal(expected_parent) != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: PR_SET_PDEATHSIG failed: %s\n",
                strerror(errno));
        _exit(127);
    }
    if (sandbox_child_set_resource_limits(
            options->memory_limit_kilobytes) != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: resource-limit setup failed: %s\n",
                strerror(errno));
        _exit(127);
    }
    if (wait_for_launch_permission(launch_read_descriptor) != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: launch cancelled before isolation: %s\n",
                strerror(errno));
        _exit(127);
    }
    (void)close(launch_read_descriptor);

    if (sandbox_child_restrict_filesystem(options->target_path) != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: Landlock filesystem isolation failed: %s\n",
                strerror(errno));
        _exit(127);
    }
    if (sandbox_child_install_network_filter() != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: seccomp network isolation failed: %s\n",
                strerror(errno));
        _exit(127);
    }
    if (sandbox_child_close_descriptors() != 0) {
        dprintf(STDERR_FILENO,
                "sandbox child: descriptor cleanup failed: %s\n",
                strerror(errno));
        _exit(127);
    }

    execve(options->target_path, options->target_argv,
           sandbox_child_environment());
    dprintf(STDERR_FILENO, "sandbox child: execve(%s) failed: %s\n",
            options->target_path, strerror(errno));
    _exit(127);
}

int main(int argc, char **argv)
{
    SandboxOptions options;
    SandboxState state;
    TimeoutMonitorConfig timeout_config;
    MemoryMonitorConfig memory_config;
    CpuMonitorConfig cpu_config;
    SandboxCgroup cgroup;
    WorkloadStatus workload_status;
    SandboxTerminationReason termination_reason = SANDBOX_TERMINATION_NONE;
    pthread_t timeout_thread;
    pthread_t memory_thread;
    pthread_t cpu_thread;
    pid_t child_pid;
    pid_t supervisor_pid = getpid();
    int launch_pipe[2] = {-1, -1};
    int child_started = 0;
    int workload_finished = 0;
    int timeout_monitor_started = 0;
    int memory_monitor_started = 0;
    int cpu_monitor_started = 0;
    int state_initialized = 0;
    int exit_code = EXIT_FAILURE;

    memset(&workload_status, 0, sizeof(workload_status));
    memset(&cgroup, 0, sizeof(cgroup));
    if (parse_options(argc, argv, &options) != 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (sandbox_state_init(&state) != 0) {
        return EXIT_FAILURE;
    }
    state_initialized = 1;
    if (enable_child_subreaper() != 0) {
        goto cleanup;
    }
    if (install_operator_signal_handlers() != 0) {
        logger_error("operator signal handler setup failed: %s",
                     strerror(errno));
        goto cleanup;
    }

    logger_info("sandbox controller starting: target=%s timeout=%u seconds "
                "memory_limit=%lu kB",
                options.target_path, options.timeout_seconds,
                options.memory_limit_kilobytes);

    (void)sandbox_cgroup_prepare(&cgroup,
                                 options.memory_limit_kilobytes);
    if (pipe2(launch_pipe, O_CLOEXEC) != 0) {
        logger_error("launch synchronization pipe failed: %s",
                     strerror(errno));
        goto cleanup;
    }

    child_pid = fork();
    if (child_pid < 0) {
        logger_error("fork() failed: %s", strerror(errno));
        goto cleanup;
    }

    if (child_pid == 0) {
        run_sandbox_child(&options, launch_pipe[0], launch_pipe[1],
                          supervisor_pid);
    }

    child_started = 1;
    (void)close(launch_pipe[0]);
    launch_pipe[0] = -1;
    if (setpgid(child_pid, child_pid) != 0 &&
        errno != EACCES && errno != ESRCH) {
        logger_error("parent setpgid(%ld) failed: %s",
                     (long)child_pid, strerror(errno));
        termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
    }

    if (sandbox_state_set_workload(&state, child_pid, child_pid) != 0) {
        logger_error("unable to initialize workload process-tree state");
        (void)kill(child_pid, SIGKILL);
        (void)waitpid(child_pid, NULL, 0);
        child_started = 0;
        goto cleanup;
    }

    if (cgroup.active && sandbox_cgroup_attach(&cgroup, child_pid) != 0) {
        logger_error("could not attach PID %ld to sandbox cgroup: %s",
                     (long)child_pid, strerror(errno));
        termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
    }

    if (operator_signal_number != 0) {
        logger_warn("operator signal %d received during workload setup",
                    (int)operator_signal_number);
        termination_reason = SANDBOX_TERMINATION_OPERATOR_SIGNAL;
    }

    if (termination_reason == SANDBOX_TERMINATION_NONE &&
        release_child(launch_pipe[1]) != 0) {
        logger_error("could not release isolated child: %s", strerror(errno));
        termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
    }
    (void)close(launch_pipe[1]);
    launch_pipe[1] = -1;

    logger_info("supervising workload: leader PID=%ld PGID=%ld "
                "subreaper PID=%ld membership=%s",
                (long)child_pid, (long)child_pid, (long)getpid(),
                cgroup.active ? "cgroup v2" : "process-tree ancestry");
    logger_info("child hardening active: Landlock filesystem allowlist, "
                "seccomp network deny, minimal environment, closed FDs, "
                "PR_SET_PDEATHSIG=SIGKILL");

    timeout_config.state = &state;
    timeout_config.timeout_seconds = options.timeout_seconds;
    timeout_config.poll_interval_milliseconds = MONITOR_POLL_MILLISECONDS;

    memory_config.state = &state;
    memory_config.cgroup = &cgroup;
    memory_config.memory_limit_kilobytes = options.memory_limit_kilobytes;
    memory_config.poll_interval_milliseconds = MEMORY_POLL_MILLISECONDS;

    cpu_config.state = &state;
    cpu_config.poll_interval_milliseconds = CPU_POLL_MILLISECONDS;

    {
        int thread_result = pthread_create(&timeout_thread, NULL,
                                           timeout_monitor_thread,
                                           &timeout_config);
        if (thread_result != 0) {
            logger_error("timeout monitor thread creation failed: %s",
                         strerror(thread_result));
            (void)sandbox_state_request_termination(
                &state, SANDBOX_TERMINATION_MONITOR_ERROR);
        } else {
            timeout_monitor_started = 1;
        }
    }

    if (options.memory_limit_kilobytes > 0u) {
        int thread_result = pthread_create(&memory_thread, NULL,
                                           memory_monitor_thread,
                                           &memory_config);
        if (thread_result != 0) {
            logger_error("memory monitor thread creation failed: %s",
                         strerror(thread_result));
            (void)sandbox_state_request_termination(
                &state, SANDBOX_TERMINATION_MONITOR_ERROR);
        } else {
            memory_monitor_started = 1;
        }
    }

    {
        int thread_result = pthread_create(&cpu_thread, NULL,
                                           cpu_monitor_thread,
                                           &cpu_config);
        if (thread_result != 0) {
            logger_error("CPU monitor thread creation failed: %s",
                         strerror(thread_result));
            (void)sandbox_state_request_termination(
                &state, SANDBOX_TERMINATION_MONITOR_ERROR);
        } else {
            cpu_monitor_started = 1;
        }
    }

    if (termination_reason != SANDBOX_TERMINATION_NONE) {
        if (terminate_workload(&state, &cgroup, termination_reason,
                               &workload_status) == 0) {
            workload_finished = 1;
        }
    } else if (supervise_workload(&state, &cgroup, &workload_status,
                                  &termination_reason) == 0) {
        workload_finished = 1;
    }

cleanup:
    if (launch_pipe[0] >= 0) {
        (void)close(launch_pipe[0]);
    }
    if (launch_pipe[1] >= 0) {
        (void)close(launch_pipe[1]);
    }
    if (child_started && !workload_finished) {
        if (termination_reason == SANDBOX_TERMINATION_NONE) {
            termination_reason = SANDBOX_TERMINATION_SUPERVISOR_ERROR;
        }
        logger_warn("performing cleanup for an active workload tree");
        if (terminate_workload(&state, &cgroup, termination_reason,
                               &workload_status) == 0) {
            workload_finished = 1;
        }
    }

    if (child_started && workload_finished) {
        (void)sandbox_state_mark_workload_exited(&state);
    }

    if (timeout_monitor_started) {
        int join_result = pthread_join(timeout_thread, NULL);

        if (join_result != 0) {
            logger_error("timeout monitor thread join failed: %s",
                         strerror(join_result));
        }
    }

    if (memory_monitor_started) {
        int join_result = pthread_join(memory_thread, NULL);

        if (join_result != 0) {
            logger_error("memory monitor thread join failed: %s",
                         strerror(join_result));
        }
    }

    if (cpu_monitor_started) {
        int join_result = pthread_join(cpu_thread, NULL);

        if (join_result != 0) {
            logger_error("CPU monitor thread join failed: %s",
                         strerror(join_result));
        }
    }

    if (workload_finished && workload_status.leader_status_available) {
        logger_info("workload cleanup complete: reaped_processes=%lu",
                    workload_status.reaped_processes);
        exit_code = report_child_status(workload_status.leader_status,
                                        termination_reason);
    } else if (child_started) {
        logger_error("original workload leader status was not collected");
    }

    if (cgroup.active) {
        (void)sandbox_cgroup_destroy(&cgroup);
    }

    if (state_initialized) {
        (void)sandbox_state_destroy(&state);
    }
    return exit_code;
}
