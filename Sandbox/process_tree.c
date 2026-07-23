#define _POSIX_C_SOURCE 200809L

#include "process_tree.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROC_PATH_MAX 64u
#define PROC_STATUS_LINE_MAX 256u
#define PROC_STAT_LINE_MAX 4096u

typedef enum ProcReadResult {
    PROC_READ_ERROR = -1,
    PROC_READ_SUCCESS = 0,
    PROC_READ_PROCESS_GONE = 1
} ProcReadResult;

static int build_proc_path(char *path, size_t path_size, pid_t pid,
                           const char *file_name)
{
    int length = snprintf(path, path_size, "/proc/%ld/%s",
                          (long)pid, file_name);

    return length >= 0 && (size_t)length < path_size ? 0 : -1;
}

static int process_gone_error(int error_code)
{
    return error_code == ENOENT || error_code == ESRCH;
}

static int parse_pid_token(const char *token, pid_t *value)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' || parsed < 0 ||
        parsed > INT_MAX) {
        return -1;
    }

    *value = (pid_t)parsed;
    return 0;
}

static int parse_unsigned_token(const char *token,
                                unsigned long long *value)
{
    char *end = NULL;

    errno = 0;
    *value = strtoull(token, &end, 10);
    return errno == 0 && end != token && *end == '\0' ? 0 : -1;
}

static ProcReadResult read_process_stat(pid_t pid,
                                        ProcessTreeProcess *process)
{
    char path[PROC_PATH_MAX];
    char line[PROC_STAT_LINE_MAX];
    char *command_end;
    char *save_pointer = NULL;
    char *token;
    unsigned int field_number = 3u;
    int found_parent = 0;
    int found_group = 0;
    int found_user_ticks = 0;
    int found_system_ticks = 0;
    FILE *stat_file;

    if (build_proc_path(path, sizeof(path), pid, "stat") != 0) {
        return PROC_READ_ERROR;
    }

    stat_file = fopen(path, "r");
    if (stat_file == NULL) {
        return process_gone_error(errno) ? PROC_READ_PROCESS_GONE
                                         : PROC_READ_ERROR;
    }

    if (fgets(line, sizeof(line), stat_file) == NULL) {
        int read_error = errno;
        int reached_end = feof(stat_file);

        fclose(stat_file);
        return reached_end || process_gone_error(read_error)
                   ? PROC_READ_PROCESS_GONE
                   : PROC_READ_ERROR;
    }

    if (fclose(stat_file) != 0) {
        return PROC_READ_ERROR;
    }

    command_end = strrchr(line, ')');
    if (command_end == NULL || command_end[1] != ' ') {
        return PROC_READ_ERROR;
    }

    memset(process, 0, sizeof(*process));
    process->pid = pid;
    token = strtok_r(command_end + 2, " \t\r\n", &save_pointer);
    while (token != NULL && field_number <= 15u) {
        if (field_number == 3u) {
            if (token[0] == '\0' || token[1] != '\0') {
                return PROC_READ_ERROR;
            }
            process->state = token[0];
        } else if (field_number == 4u) {
            if (parse_pid_token(token, &process->parent_pid) != 0) {
                return PROC_READ_ERROR;
            }
            found_parent = 1;
        } else if (field_number == 5u) {
            if (parse_pid_token(token, &process->process_group_id) != 0) {
                return PROC_READ_ERROR;
            }
            found_group = 1;
        } else if (field_number == 14u) {
            if (parse_unsigned_token(token, &process->user_ticks) != 0) {
                return PROC_READ_ERROR;
            }
            found_user_ticks = 1;
        } else if (field_number == 15u) {
            if (parse_unsigned_token(token, &process->system_ticks) != 0) {
                return PROC_READ_ERROR;
            }
            found_system_ticks = 1;
        }

        token = strtok_r(NULL, " \t\r\n", &save_pointer);
        field_number++;
    }

    return found_parent && found_group && found_user_ticks &&
                   found_system_ticks
               ? PROC_READ_SUCCESS
               : PROC_READ_ERROR;
}

static ProcReadResult read_process_memory(pid_t pid,
                                          unsigned long *memory_kilobytes,
                                          int *used_virtual_fallback)
{
    char path[PROC_PATH_MAX];
    char line[PROC_STATUS_LINE_MAX];
    unsigned long virtual_size = 0u;
    int found_virtual_size = 0;
    FILE *status_file;

    *memory_kilobytes = 0u;
    *used_virtual_fallback = 0;
    if (build_proc_path(path, sizeof(path), pid, "status") != 0) {
        return PROC_READ_ERROR;
    }

    status_file = fopen(path, "r");
    if (status_file == NULL) {
        return process_gone_error(errno) ? PROC_READ_PROCESS_GONE
                                         : PROC_READ_ERROR;
    }

    while (fgets(line, sizeof(line), status_file) != NULL) {
        unsigned long value;
        char unit[8];

        if (sscanf(line, "VmRSS: %lu %7s", &value, unit) == 2 &&
            strcmp(unit, "kB") == 0) {
            *memory_kilobytes = value;
            if (fclose(status_file) != 0) {
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

    {
        int read_failed = ferror(status_file);
        int close_failed = fclose(status_file) != 0;

        if (read_failed || close_failed) {
            return PROC_READ_ERROR;
        }
    }

    if (found_virtual_size) {
        *memory_kilobytes = virtual_size;
        *used_virtual_fallback = 1;
    }
    return PROC_READ_SUCCESS;
}

static int directory_name_to_pid(const char *name, pid_t *pid)
{
    const unsigned char *cursor = (const unsigned char *)name;

    if (*cursor == '\0') {
        return -1;
    }
    while (*cursor != '\0') {
        if (!isdigit(*cursor)) {
            return -1;
        }
        cursor++;
    }
    return parse_pid_token(name, pid);
}

static int append_process(ProcessTreeProcess **processes, size_t *count,
                          size_t *capacity,
                          const ProcessTreeProcess *process)
{
    ProcessTreeProcess *resized;
    size_t new_capacity;

    if (*count < *capacity) {
        (*processes)[(*count)++] = *process;
        return 0;
    }

    new_capacity = *capacity == 0u ? 128u : *capacity * 2u;
    if (new_capacity < *capacity ||
        new_capacity > SIZE_MAX / sizeof(**processes)) {
        return -1;
    }

    resized = realloc(*processes, new_capacity * sizeof(**processes));
    if (resized == NULL) {
        return -1;
    }
    *processes = resized;
    *capacity = new_capacity;
    (*processes)[(*count)++] = *process;
    return 0;
}

static int collect_all_processes(ProcessTreeProcess **processes,
                                 size_t *process_count)
{
    DIR *proc_directory;
    struct dirent *entry;
    size_t capacity = 0u;

    *processes = NULL;
    *process_count = 0u;
    proc_directory = opendir("/proc");
    if (proc_directory == NULL) {
        return -1;
    }

    for (;;) {
        ProcessTreeProcess process;
        pid_t pid;
        ProcReadResult read_result;

        errno = 0;
        entry = readdir(proc_directory);
        if (entry == NULL) {
            if (errno != 0) {
                free(*processes);
                *processes = NULL;
                *process_count = 0u;
                closedir(proc_directory);
                return -1;
            }
            break;
        }

        if (directory_name_to_pid(entry->d_name, &pid) != 0) {
            continue;
        }
        read_result = read_process_stat(pid, &process);
        if (read_result == PROC_READ_PROCESS_GONE) {
            continue;
        }
        if (read_result == PROC_READ_ERROR ||
            append_process(processes, process_count, &capacity,
                           &process) != 0) {
            free(*processes);
            *processes = NULL;
            *process_count = 0u;
            closedir(proc_directory);
            return -1;
        }
    }

    if (closedir(proc_directory) != 0) {
        free(*processes);
        *processes = NULL;
        *process_count = 0u;
        return -1;
    }
    return 0;
}

static int process_is_selected_parent(const ProcessTreeProcess *processes,
                                      const unsigned char *selected,
                                      size_t process_count, pid_t parent_pid)
{
    size_t index;

    for (index = 0u; index < process_count; index++) {
        if (selected[index] && processes[index].pid == parent_pid) {
            return 1;
        }
    }
    return 0;
}

void process_tree_sample_destroy(ProcessTreeSample *sample)
{
    if (sample == NULL) {
        return;
    }
    free(sample->processes);
    memset(sample, 0, sizeof(*sample));
}

int process_tree_sample(pid_t supervisor_pid, pid_t leader_pid,
                        int leader_alive, ProcessTreeSample *sample)
{
    ProcessTreeProcess *all_processes = NULL;
    unsigned char *selected = NULL;
    size_t all_count = 0u;
    size_t selected_count = 0u;
    size_t index;
    int changed;

    if (sample == NULL || supervisor_pid <= 0) {
        return -1;
    }
    memset(sample, 0, sizeof(*sample));

    if (collect_all_processes(&all_processes, &all_count) != 0) {
        return -1;
    }

    selected = calloc(all_count == 0u ? 1u : all_count, sizeof(*selected));
    if (selected == NULL) {
        free(all_processes);
        return -1;
    }

    for (index = 0u; index < all_count; index++) {
        if ((leader_alive && all_processes[index].pid == leader_pid) ||
            all_processes[index].parent_pid == supervisor_pid) {
            selected[index] = 1u;
        }
    }

    do {
        changed = 0;
        for (index = 0u; index < all_count; index++) {
            if (!selected[index] &&
                process_is_selected_parent(all_processes, selected, all_count,
                                           all_processes[index].parent_pid)) {
                selected[index] = 1u;
                changed = 1;
            }
        }
    } while (changed);

    for (index = 0u; index < all_count; index++) {
        if (selected[index]) {
            selected_count++;
        }
    }

    if (selected_count > 0u) {
        sample->processes = calloc(selected_count, sizeof(*sample->processes));
        if (sample->processes == NULL) {
            free(selected);
            free(all_processes);
            return -1;
        }
    }

    for (index = 0u; index < all_count; index++) {
        unsigned long process_memory = 0u;
        int used_virtual_fallback = 0;
        ProcReadResult memory_result;

        if (!selected[index]) {
            continue;
        }
        sample->processes[sample->process_count++] = all_processes[index];

        if (ULLONG_MAX - sample->user_ticks <
            all_processes[index].user_ticks) {
            sample->user_ticks = ULLONG_MAX;
        } else {
            sample->user_ticks += all_processes[index].user_ticks;
        }
        if (ULLONG_MAX - sample->system_ticks <
            all_processes[index].system_ticks) {
            sample->system_ticks = ULLONG_MAX;
        } else {
            sample->system_ticks += all_processes[index].system_ticks;
        }

        memory_result = read_process_memory(all_processes[index].pid,
                                            &process_memory,
                                            &used_virtual_fallback);
        if (memory_result == PROC_READ_ERROR) {
            process_tree_sample_destroy(sample);
            free(selected);
            free(all_processes);
            return -1;
        }
        if (memory_result == PROC_READ_SUCCESS) {
            if (ULONG_MAX - sample->memory_kilobytes < process_memory) {
                sample->memory_kilobytes = ULONG_MAX;
            } else {
                sample->memory_kilobytes += process_memory;
            }
            if (used_virtual_fallback) {
                sample->used_virtual_memory_fallback = 1;
            }
        }
    }

    free(selected);
    free(all_processes);
    return 0;
}
