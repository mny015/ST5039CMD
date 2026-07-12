#ifndef TASK2_MONITOR_H
#define TASK2_MONITOR_H

#include <pthread.h>
#include <sys/types.h>

typedef enum SandboxTerminationReason {
    SANDBOX_TERMINATION_NONE = 0,
    SANDBOX_TERMINATION_TIMEOUT = 1,
    SANDBOX_TERMINATION_MONITOR_ERROR = 2,
    SANDBOX_TERMINATION_SUPERVISOR_ERROR = 3
} SandboxTerminationReason;

typedef struct SandboxState {
    pid_t child_pid;
    int child_alive;
    int termination_requested;
    SandboxTerminationReason termination_reason;
    pthread_mutex_t mutex;
} SandboxState;

typedef struct SandboxStateSnapshot {
    pid_t child_pid;
    int child_alive;
    int termination_requested;
    SandboxTerminationReason termination_reason;
} SandboxStateSnapshot;

typedef struct TimeoutMonitorConfig {
    SandboxState *state;
    unsigned int timeout_seconds;
    unsigned int poll_interval_milliseconds;
} TimeoutMonitorConfig;

int sandbox_state_init(SandboxState *state);
int sandbox_state_set_child(SandboxState *state, pid_t child_pid);
int sandbox_state_snapshot(SandboxState *state,
                           SandboxStateSnapshot *snapshot);
int sandbox_state_request_termination(SandboxState *state,
                                      SandboxTerminationReason reason);
int sandbox_state_mark_child_exited(SandboxState *state);
int sandbox_state_destroy(SandboxState *state);

const char *sandbox_termination_reason_name(SandboxTerminationReason reason);
void *timeout_monitor_thread(void *argument);

#endif
