#ifndef TASK2_MONITOR_H
#define TASK2_MONITOR_H

#include <pthread.h>
#include <sys/types.h>

typedef enum SandboxTerminationReason {
    SANDBOX_TERMINATION_NONE = 0,
    SANDBOX_TERMINATION_TIMEOUT = 1,
    SANDBOX_TERMINATION_MEMORY_LIMIT = 2,
    SANDBOX_TERMINATION_MONITOR_ERROR = 3,
    SANDBOX_TERMINATION_SUPERVISOR_ERROR = 4
} SandboxTerminationReason;

typedef struct SandboxState {
    pid_t supervisor_pid;
    pid_t child_pid;
    pid_t child_process_group_id;
    int leader_alive;
    int workload_alive;
    int termination_requested;
    SandboxTerminationReason termination_reason;
    pthread_mutex_t mutex;
} SandboxState;

typedef struct SandboxStateSnapshot {
    pid_t supervisor_pid;
    pid_t child_pid;
    pid_t child_process_group_id;
    int leader_alive;
    int workload_alive;
    int termination_requested;
    SandboxTerminationReason termination_reason;
} SandboxStateSnapshot;

typedef struct TimeoutMonitorConfig {
    SandboxState *state;
    unsigned int timeout_seconds;
    unsigned int poll_interval_milliseconds;
} TimeoutMonitorConfig;

typedef struct MemoryMonitorConfig {
    SandboxState *state;
    unsigned long memory_limit_kilobytes;
    unsigned int poll_interval_milliseconds;
} MemoryMonitorConfig;

typedef struct CpuMonitorConfig {
    SandboxState *state;
    unsigned int poll_interval_milliseconds;
} CpuMonitorConfig;

int sandbox_state_init(SandboxState *state);
int sandbox_state_set_workload(SandboxState *state, pid_t child_pid,
                               pid_t child_process_group_id);
int sandbox_state_snapshot(SandboxState *state,
                           SandboxStateSnapshot *snapshot);
int sandbox_state_request_termination(SandboxState *state,
                                      SandboxTerminationReason reason);
int sandbox_state_mark_leader_exited(SandboxState *state);
int sandbox_state_mark_workload_exited(SandboxState *state);
int sandbox_state_destroy(SandboxState *state);

const char *sandbox_termination_reason_name(SandboxTerminationReason reason);
void *timeout_monitor_thread(void *argument);
void *memory_monitor_thread(void *argument);
void *cpu_monitor_thread(void *argument);

#endif
