#define _GNU_SOURCE

#include "security.h"

#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER 0ULL
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE 0ULL
#endif

#if defined(__x86_64__)
#define SANDBOX_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SANDBOX_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "The sandbox seccomp filter needs an audit architecture definition"
#endif

static int write_text_file(const char *directory, const char *name,
                           const char *value)
{
    char path[SANDBOX_CGROUP_PATH_CAPACITY];
    int descriptor;
    int path_length;
    size_t length = strlen(value);
    ssize_t written;

    path_length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    descriptor = open(path, O_WRONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }

    do {
        written = write(descriptor, value, length);
    } while (written < 0 && errno == EINTR);

    if (written < 0 || (size_t)written != length) {
        int saved_errno = written < 0 ? errno : EIO;

        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }

    if (close(descriptor) != 0) {
        return -1;
    }
    return 0;
}

static int read_unsigned_file(const char *directory, const char *name,
                              unsigned long long *value)
{
    char path[SANDBOX_CGROUP_PATH_CAPACITY];
    char buffer[128];
    char *end = NULL;
    FILE *stream;
    unsigned long long parsed;
    int path_length;

    path_length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    stream = fopen(path, "r");
    if (stream == NULL) {
        return -1;
    }
    if (fgets(buffer, sizeof(buffer), stream) == NULL) {
        int saved_errno = ferror(stream) ? errno : EIO;

        (void)fclose(stream);
        errno = saved_errno;
        return -1;
    }
    if (fclose(stream) != 0) {
        return -1;
    }

    errno = 0;
    parsed = strtoull(buffer, &end, 10);
    if (errno != 0 || end == buffer || (*end != '\n' && *end != '\0')) {
        errno = EINVAL;
        return -1;
    }
    *value = parsed;
    return 0;
}

static int current_cgroup_directory(char *directory, size_t capacity)
{
    char line[SANDBOX_CGROUP_PATH_CAPACITY];
    FILE *stream = fopen("/proc/self/cgroup", "r");

    if (stream == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), stream) != NULL) {
        char *path;
        size_t length;
        int path_length;

        if (strncmp(line, "0::", 3u) != 0) {
            continue;
        }
        path = line + 3;
        length = strcspn(path, "\r\n");
        path[length] = '\0';
        if (*path != '/') {
            (void)fclose(stream);
            errno = EINVAL;
            return -1;
        }
        path_length = snprintf(directory, capacity, "/sys/fs/cgroup%s", path);
        if (path_length < 0 || (size_t)path_length >= capacity) {
            (void)fclose(stream);
            errno = ENAMETOOLONG;
            return -1;
        }
        (void)fclose(stream);
        return 0;
    }

    (void)fclose(stream);
    errno = ENOTSUP;
    return -1;
}

int sandbox_cgroup_prepare(SandboxCgroup *cgroup,
                           unsigned long memory_limit_kilobytes)
{
    char parent[SANDBOX_CGROUP_PATH_CAPACITY];
    char value[64];
    unsigned long long memory_bytes;
    int path_length;

    memset(cgroup, 0, sizeof(*cgroup));
    if (current_cgroup_directory(parent, sizeof(parent)) != 0) {
        logger_warn("cgroup v2 unavailable: %s", strerror(errno));
        return 0;
    }

    path_length = snprintf(cgroup->path, sizeof(cgroup->path),
                           "%s/st5039cmd-%ld", parent, (long)getpid());
    if (path_length < 0 || (size_t)path_length >= sizeof(cgroup->path)) {
        logger_warn("cgroup path is too long; using process-tree fallback");
        cgroup->path[0] = '\0';
        return 0;
    }

    if (mkdir(cgroup->path, 0700) != 0) {
        logger_warn("cgroup delegation unavailable at %s: %s",
                    parent, strerror(errno));
        cgroup->path[0] = '\0';
        return 0;
    }

    if (memory_limit_kilobytes > 0u) {
        memory_bytes = (unsigned long long)memory_limit_kilobytes * 1024ULL;
        (void)snprintf(value, sizeof(value), "%llu", memory_bytes);
        if (write_text_file(cgroup->path, "memory.max", value) != 0) {
            logger_warn("cgroup memory controller unavailable: %s",
                        strerror(errno));
            (void)rmdir(cgroup->path);
            cgroup->path[0] = '\0';
            return 0;
        }
        if (write_text_file(cgroup->path, "memory.oom.group", "1") != 0) {
            logger_warn("could not enable cgroup OOM group handling: %s",
                        strerror(errno));
        }
        if (write_text_file(cgroup->path, "memory.swap.max", "0") != 0 &&
            errno != ENOENT) {
            logger_warn("could not disable cgroup swap: %s", strerror(errno));
        }
    }

    cgroup->active = 1;
    logger_info("dedicated cgroup v2 prepared: %s", cgroup->path);
    return 1;
}

int sandbox_cgroup_attach(const SandboxCgroup *cgroup, pid_t child_pid)
{
    char value[64];

    if (!cgroup->active) {
        return 0;
    }
    (void)snprintf(value, sizeof(value), "%ld", (long)child_pid);
    return write_text_file(cgroup->path, "cgroup.procs", value);
}

int sandbox_cgroup_read_memory_kilobytes(const SandboxCgroup *cgroup,
                                         unsigned long *memory_kilobytes)
{
    unsigned long long memory_bytes;

    if (!cgroup->active ||
        read_unsigned_file(cgroup->path, "memory.current", &memory_bytes) != 0) {
        return -1;
    }
    if (memory_bytes / 1024ULL > (unsigned long long)ULONG_MAX) {
        *memory_kilobytes = ULONG_MAX;
    } else {
        *memory_kilobytes = (unsigned long)(memory_bytes / 1024ULL);
    }
    return 0;
}

int sandbox_cgroup_is_populated(const SandboxCgroup *cgroup)
{
    char path[SANDBOX_CGROUP_PATH_CAPACITY];
    char line[128];
    FILE *stream;
    int path_length;

    if (!cgroup->active) {
        return 0;
    }
    path_length = snprintf(path, sizeof(path), "%s/cgroup.events",
                           cgroup->path);
    if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    stream = fopen(path, "r");
    if (stream == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        int populated;

        if (sscanf(line, "populated %d", &populated) == 1) {
            (void)fclose(stream);
            return populated != 0;
        }
    }
    (void)fclose(stream);
    errno = EIO;
    return -1;
}

int sandbox_cgroup_kill(const SandboxCgroup *cgroup)
{
    if (!cgroup->active) {
        return 0;
    }
    return write_text_file(cgroup->path, "cgroup.kill", "1");
}

int sandbox_cgroup_destroy(SandboxCgroup *cgroup)
{
    if (!cgroup->active) {
        return 0;
    }
    if (rmdir(cgroup->path) != 0) {
        logger_warn("could not remove sandbox cgroup %s: %s",
                    cgroup->path, strerror(errno));
        return -1;
    }
    cgroup->active = 0;
    cgroup->path[0] = '\0';
    return 0;
}

int sandbox_child_set_parent_death_signal(pid_t expected_parent)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
        return -1;
    }
    if (getppid() != expected_parent) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

int sandbox_child_set_resource_limits(unsigned long memory_limit_kilobytes)
{
    struct rlimit core_limit;

    core_limit.rlim_cur = 0;
    core_limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
        return -1;
    }

    if (memory_limit_kilobytes > 0u) {
        struct rlimit memory_limit;
        unsigned long long bytes =
            (unsigned long long)memory_limit_kilobytes * 1024ULL;

        memory_limit.rlim_cur = (rlim_t)bytes;
        memory_limit.rlim_max = (rlim_t)bytes;
        if ((unsigned long long)memory_limit.rlim_cur != bytes) {
            errno = EOVERFLOW;
            return -1;
        }
        if (setrlimit(RLIMIT_AS, &memory_limit) != 0) {
            return -1;
        }
    }
    return 0;
}

static int add_landlock_path_rule(int ruleset_descriptor, const char *path,
                                  uint64_t allowed_access, int required)
{
    struct landlock_path_beneath_attr rule;
    int path_descriptor = open(path, O_PATH | O_CLOEXEC);

    if (path_descriptor < 0) {
        return required ? -1 : 0;
    }
    memset(&rule, 0, sizeof(rule));
    rule.allowed_access = allowed_access;
    rule.parent_fd = path_descriptor;
    if (syscall(SYS_landlock_add_rule, ruleset_descriptor,
                LANDLOCK_RULE_PATH_BENEATH, &rule, 0u) != 0) {
        int saved_errno = errno;

        (void)close(path_descriptor);
        errno = saved_errno;
        return -1;
    }
    (void)close(path_descriptor);
    return 0;
}

static int resolve_target_directory(const char *target_path,
                                    char *directory, size_t capacity)
{
    char resolved[SANDBOX_CGROUP_PATH_CAPACITY];
    char *separator;

    if (realpath(target_path, resolved) == NULL) {
        return -1;
    }
    separator = strrchr(resolved, '/');
    if (separator == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (separator == resolved) {
        separator[1] = '\0';
    } else {
        *separator = '\0';
    }
    if (strlen(resolved) >= capacity) {
        errno = ENAMETOOLONG;
        return -1;
    }
    (void)strcpy(directory, resolved);
    return 0;
}

int sandbox_child_restrict_filesystem(const char *target_path)
{
    struct landlock_ruleset_attr ruleset;
    uint64_t handled_access;
    const uint64_t runtime_directory_access =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR;
    const uint64_t runtime_file_access =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE;
    int abi;
    int ruleset_descriptor;
    char target_directory[SANDBOX_CGROUP_PATH_CAPACITY];

    if (resolve_target_directory(target_path, target_directory,
                                 sizeof(target_directory)) != 0) {
        return -1;
    }

    abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                       LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        errno = abi < 0 ? errno : ENOTSUP;
        return -1;
    }

    handled_access = LANDLOCK_ACCESS_FS_EXECUTE |
                     LANDLOCK_ACCESS_FS_WRITE_FILE |
                     LANDLOCK_ACCESS_FS_READ_FILE |
                     LANDLOCK_ACCESS_FS_READ_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE |
                     LANDLOCK_ACCESS_FS_MAKE_CHAR |
                     LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG |
                     LANDLOCK_ACCESS_FS_MAKE_SOCK |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO |
                     LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                     LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2) {
        handled_access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if (abi >= 3) {
        handled_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    memset(&ruleset, 0, sizeof(ruleset));
    ruleset.handled_access_fs = handled_access;
    ruleset_descriptor = (int)syscall(SYS_landlock_create_ruleset,
                                      &ruleset, sizeof(ruleset), 0u);
    if (ruleset_descriptor < 0) {
        return -1;
    }

    if (add_landlock_path_rule(ruleset_descriptor, target_path,
                               runtime_file_access, 1) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, target_directory,
                               runtime_directory_access, 1) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/usr",
                               runtime_directory_access, 1) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/lib",
                               runtime_directory_access, 0) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/lib64",
                               runtime_directory_access, 0) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/etc/ld.so.cache",
                               LANDLOCK_ACCESS_FS_READ_FILE, 0) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/etc/ld.so.preload",
                               LANDLOCK_ACCESS_FS_READ_FILE, 0) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/dev/null",
                               LANDLOCK_ACCESS_FS_READ_FILE |
                                   LANDLOCK_ACCESS_FS_WRITE_FILE,
                               0) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/dev/urandom",
                               LANDLOCK_ACCESS_FS_READ_FILE, 0) != 0 ||
        add_landlock_path_rule(ruleset_descriptor, "/dev/random",
                               LANDLOCK_ACCESS_FS_READ_FILE, 0) != 0) {
        int saved_errno = errno;

        (void)close(ruleset_descriptor);
        errno = saved_errno;
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        syscall(SYS_landlock_restrict_self, ruleset_descriptor, 0u) != 0) {
        int saved_errno = errno;

        (void)close(ruleset_descriptor);
        errno = saved_errno;
        return -1;
    }
    return close(ruleset_descriptor);
}

static const int blocked_network_syscalls[] = {
#ifdef __NR_socket
    __NR_socket,
#endif
#ifdef __NR_socketpair
    __NR_socketpair,
#endif
#ifdef __NR_connect
    __NR_connect,
#endif
#ifdef __NR_bind
    __NR_bind,
#endif
#ifdef __NR_listen
    __NR_listen,
#endif
#ifdef __NR_accept
    __NR_accept,
#endif
#ifdef __NR_accept4
    __NR_accept4,
#endif
#ifdef __NR_sendto
    __NR_sendto,
#endif
#ifdef __NR_sendmsg
    __NR_sendmsg,
#endif
#ifdef __NR_sendmmsg
    __NR_sendmmsg,
#endif
#ifdef __NR_recvfrom
    __NR_recvfrom,
#endif
#ifdef __NR_recvmsg
    __NR_recvmsg,
#endif
#ifdef __NR_recvmmsg
    __NR_recvmmsg,
#endif
#ifdef __NR_shutdown
    __NR_shutdown,
#endif
#ifdef __NR_setsockopt
    __NR_setsockopt,
#endif
#ifdef __NR_getsockopt
    __NR_getsockopt,
#endif
};

int sandbox_child_install_network_filter(void)
{
    struct sock_filter filter[64];
    struct sock_fprog program;
    size_t filter_length = 0u;
    size_t index;

    filter[filter_length++] =
        (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                     offsetof(struct seccomp_data, arch));
    filter[filter_length++] =
        (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                     SANDBOX_AUDIT_ARCH, 1, 0);
    filter[filter_length++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                     SECCOMP_RET_KILL_PROCESS);
    filter[filter_length++] =
        (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                     offsetof(struct seccomp_data, nr));

    for (index = 0u;
         index < sizeof(blocked_network_syscalls) /
                     sizeof(blocked_network_syscalls[0]);
         index++) {
        filter[filter_length++] =
            (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                         (uint32_t)blocked_network_syscalls[index],
                                         0, 1);
        filter[filter_length++] =
            (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                         SECCOMP_RET_ERRNO |
                                             (uint32_t)EPERM);
    }
    filter[filter_length++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    program.len = (unsigned short)filter_length;
    program.filter = filter;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

int sandbox_child_close_descriptors(void)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3u, UINT_MAX, 0u) == 0) {
        return 0;
    }
    if (errno != ENOSYS && errno != EINVAL) {
        return -1;
    }
#endif
    {
        long maximum = sysconf(_SC_OPEN_MAX);
        int descriptor;

        if (maximum < 0 || maximum > 1048576L) {
            maximum = 1048576L;
        }
        for (descriptor = 3; descriptor < maximum; descriptor++) {
            (void)close(descriptor);
        }
    }
    return 0;
}

char *const *sandbox_child_environment(void)
{
    static char *const environment[] = {
        "PATH=/usr/bin:/bin",
        "LANG=C",
        "LC_ALL=C",
        "HOME=/nonexistent",
        "TMPDIR=/tmp",
        NULL
    };

    return environment;
}
