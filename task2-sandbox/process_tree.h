#ifndef TASK2_PROCESS_TREE_H
#define TASK2_PROCESS_TREE_H

#include <stddef.h>
#include <sys/types.h>

typedef struct ProcessTreeProcess {
    pid_t pid;
    pid_t parent_pid;
    pid_t process_group_id;
    char state;
    unsigned long long user_ticks;
    unsigned long long system_ticks;
} ProcessTreeProcess;

typedef struct ProcessTreeSample {
    ProcessTreeProcess *processes;
    size_t process_count;
    unsigned long memory_kilobytes;
    unsigned long long user_ticks;
    unsigned long long system_ticks;
    int used_virtual_memory_fallback;
} ProcessTreeSample;

int process_tree_sample(pid_t supervisor_pid, pid_t leader_pid,
                        int leader_alive, ProcessTreeSample *sample);
void process_tree_sample_destroy(ProcessTreeSample *sample);

#endif
