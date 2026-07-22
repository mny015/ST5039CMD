#ifndef TASK2_SECURITY_H
#define TASK2_SECURITY_H

#include <stddef.h>
#include <sys/types.h>

#define SANDBOX_CGROUP_PATH_CAPACITY 4096u

typedef struct SandboxCgroup {
    char path[SANDBOX_CGROUP_PATH_CAPACITY];
    int active;
} SandboxCgroup;

int sandbox_cgroup_prepare(SandboxCgroup *cgroup,
                           unsigned long memory_limit_kilobytes);
int sandbox_cgroup_attach(const SandboxCgroup *cgroup, pid_t child_pid);
int sandbox_cgroup_read_memory_kilobytes(const SandboxCgroup *cgroup,
                                         unsigned long *memory_kilobytes);
int sandbox_cgroup_is_populated(const SandboxCgroup *cgroup);
int sandbox_cgroup_kill(const SandboxCgroup *cgroup);
int sandbox_cgroup_destroy(SandboxCgroup *cgroup);

int sandbox_child_set_parent_death_signal(pid_t expected_parent);
int sandbox_child_set_resource_limits(unsigned long memory_limit_kilobytes);
int sandbox_child_restrict_filesystem(const char *target_path);
int sandbox_child_install_network_filter(void);
int sandbox_child_close_descriptors(void);
char *const *sandbox_child_environment(void);

#endif
