#define _GNU_SOURCE

#include "auth_protocol.h"
#include "secure_memory.h"

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define PROC_STATUS_PATH "/proc/self/status"
#define PROC_STATUS_LINE_MAX 256u
#define BACKEND_LISTEN_BACKLOG 4
#define CREDENTIALS_FILE_NAME "credentials.demo"
#define CREDENTIAL_LINE_MAX (AUTH_USERNAME_MAX + AUTH_PASSWORD_MAX + 4u)

typedef struct DemoCredential {
    char username[AUTH_USERNAME_MAX + 1u];
    char password[AUTH_PASSWORD_MAX + 1u];
} DemoCredential;

static void log_uids(FILE *out, const char *stage)
{
    uid_t real_uid = getuid();
    uid_t effective_uid = geteuid();

    fprintf(out, "[backend] %s getuid(): %lu\n",
            stage, (unsigned long)real_uid);
    fprintf(out, "[backend] %s geteuid(): %lu\n",
            stage, (unsigned long)effective_uid);
}

static int log_proc_status_uid_lines(FILE *out, const char *stage)
{
    FILE *status_file;
    char line[PROC_STATUS_LINE_MAX];
    int found_uid_line = 0;

    status_file = fopen(PROC_STATUS_PATH, "r");
    if (status_file == NULL) {
        fprintf(out, "[backend] unable to open %s: %s\n",
                PROC_STATUS_PATH, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), status_file) != NULL) {
        if (strncmp(line, "Uid:", 4u) == 0) {
            fprintf(out, "[backend] %s /proc/self/status %s", stage, line);
            found_uid_line = 1;
        }
    }

    if (ferror(status_file)) {
        fprintf(out, "[backend] error reading %s: %s\n",
                PROC_STATUS_PATH, strerror(errno));
        fclose(status_file);
        return -1;
    }

    if (fclose(status_file) != 0) {
        fprintf(out, "[backend] error closing %s: %s\n",
                PROC_STATUS_PATH, strerror(errno));
        return -1;
    }

    if (!found_uid_line) {
        fprintf(out, "[backend] no Uid line found in %s\n", PROC_STATUS_PATH);
        return -1;
    }

    return 0;
}

static void discard_remaining_file_line(FILE *file)
{
    int ch;

    while ((ch = fgetc(file)) != '\n' && ch != EOF) {
    }
}

static int resolve_demo_credential_path(char *path, size_t path_size, FILE *out)
{
    char *build_separator;
    char *executable_separator;
    ssize_t path_length;
    size_t remaining;

    path_length = readlink("/proc/self/exe", path, path_size - 1u);
    if (path_length < 0) {
        fprintf(out, "[backend] unable to resolve /proc/self/exe: %s\n",
                strerror(errno));
        return -1;
    }

    if ((size_t)path_length >= path_size - 1u) {
        fputs("[backend] backend executable path is too long\n", out);
        return -1;
    }
    path[path_length] = '\0';

    executable_separator = strrchr(path, '/');
    if (executable_separator == NULL) {
        fputs("[backend] invalid backend executable path\n", out);
        return -1;
    }
    *executable_separator = '\0';

    build_separator = strrchr(path, '/');
    if (build_separator == NULL) {
        fputs("[backend] unable to locate task1-auth directory\n", out);
        return -1;
    }
    build_separator++;

    remaining = path_size - (size_t)(build_separator - path);
    if (sizeof(CREDENTIALS_FILE_NAME) > remaining) {
        fputs("[backend] demo credential path is too long\n", out);
        return -1;
    }

    memcpy(build_separator, CREDENTIALS_FILE_NAME,
           sizeof(CREDENTIALS_FILE_NAME));
    return 0;
}

static int load_demo_credential(const char *path, DemoCredential *credential,
                                FILE *out)
{
    FILE *file = NULL;
    char line[CREDENTIAL_LINE_MAX];
    int found_credential = 0;
    int result = -1;

    memset(credential, 0, sizeof(*credential));
    memset(line, 0, sizeof(line));

    file = fopen(path, "r");
    if (file == NULL) {
        fprintf(out, "[backend] unable to open demo credential file %s: %s\n",
                path, strerror(errno));
        goto cleanup;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *separator;
        size_t line_length = strcspn(line, "\r\n");
        size_t username_length;
        size_t password_length;

        if (line[line_length] == '\0' && !feof(file)) {
            discard_remaining_file_line(file);
            fputs("[backend] demo credential line is too long\n", out);
            goto cleanup;
        }

        line[line_length] = '\0';
        if (line[0] == '\0' || line[0] == '#') {
            secure_clear(line, sizeof(line));
            continue;
        }

        if (found_credential) {
            fputs("[backend] demo credential file must contain one account\n", out);
            goto cleanup;
        }

        separator = strchr(line, ':');
        if (separator == NULL || strchr(separator + 1, ':') != NULL) {
            fputs("[backend] invalid demo credential format\n", out);
            goto cleanup;
        }

        *separator = '\0';
        username_length = strlen(line);
        password_length = strlen(separator + 1);

        if (username_length == 0u || username_length > AUTH_USERNAME_MAX ||
            password_length == 0u || password_length > AUTH_PASSWORD_MAX) {
            fputs("[backend] invalid demo credential lengths\n", out);
            goto cleanup;
        }

        memcpy(credential->username, line, username_length + 1u);
        memcpy(credential->password, separator + 1, password_length + 1u);
        found_credential = 1;
        secure_clear(line, sizeof(line));
    }

    if (ferror(file)) {
        fprintf(out, "[backend] error reading demo credential file: %s\n",
                strerror(errno));
        goto cleanup;
    }

    if (!found_credential) {
        fputs("[backend] demo credential file contains no account\n", out);
        goto cleanup;
    }

    fprintf(out, "[backend] loaded demo credential account from %s\n", path);
    result = 0;

cleanup:
    if (file != NULL && fclose(file) != 0) {
        fprintf(out, "[backend] error closing demo credential file: %s\n",
                strerror(errno));
        result = -1;
    }
    secure_clear(line, sizeof(line));
    if (result != 0) {
        secure_clear(credential, sizeof(*credential));
    }
    return result;
}

static int drop_privileges_permanently(uid_t uid, gid_t gid, FILE *out)
{
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;

    if (uid == 0) {
        fputs("[backend] refusing to use root as the privilege-drop target\n", out);
        return -1;
    }

    log_uids(out, "before privilege drop");
    (void)log_proc_status_uid_lines(out, "before privilege drop");

    if (geteuid() == 0 && setgroups(0, NULL) != 0) {
        fprintf(out, "[backend] setgroups() failed: %s\n", strerror(errno));
        return -1;
    }

    if (setresgid(gid, gid, gid) != 0) {
        fprintf(out, "[backend] setresgid() failed: %s\n", strerror(errno));
        return -1;
    }

    if (setresuid(uid, uid, uid) != 0) {
        fprintf(out, "[backend] setresuid() failed: %s\n", strerror(errno));
        return -1;
    }

    log_uids(out, "after privilege drop");
    (void)log_proc_status_uid_lines(out, "after privilege drop");

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0) {
        fprintf(out, "[backend] getresuid() failed: %s\n", strerror(errno));
        return -1;
    }

    if (real_uid != uid || effective_uid != uid || saved_uid != uid) {
        fputs("[backend] UID runtime check failed after privilege drop\n", out);
        return -1;
    }

    errno = 0;
    if (seteuid(0) == 0) {
        fputs("[backend] privilege drop was reversible; root was regained\n", out);
        (void)seteuid(uid);
        return -1;
    }

    if (errno != EPERM) {
        fprintf(out, "[backend] unexpected root-regain check error: %s\n",
                strerror(errno));
        return -1;
    }

    fprintf(out, "[backend] privileges permanently dropped to UID %lu GID %lu\n",
            (unsigned long)uid, (unsigned long)gid);
    return 0;
}

static void close_logged(int fd, FILE *out, const char *label)
{
    if (fd >= 0 && close(fd) != 0) {
        fprintf(out, "[backend] error closing %s: %s\n", label, strerror(errno));
    }
}

static void unlink_socket_path(FILE *out)
{
    if (unlink(AUTH_SOCKET_PATH) != 0 && errno != ENOENT) {
        fprintf(out, "[backend] unable to remove %s: %s\n",
                AUTH_SOCKET_PATH, strerror(errno));
    }
}

static int create_server_socket(FILE *out)
{
    int server_fd;
    struct sockaddr_un address;
    size_t path_length;

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(out, "[backend] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;

    path_length = strlen(AUTH_SOCKET_PATH);
    if (path_length >= sizeof(address.sun_path)) {
        fprintf(out, "[backend] socket path too long: %s\n", AUTH_SOCKET_PATH);
        close_logged(server_fd, out, "server socket");
        return -1;
    }

    memcpy(address.sun_path, AUTH_SOCKET_PATH, path_length + 1u);
    unlink_socket_path(out);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(out, "[backend] bind(%s) failed: %s\n",
                AUTH_SOCKET_PATH, strerror(errno));
        close_logged(server_fd, out, "server socket");
        return -1;
    }

    if (chmod(AUTH_SOCKET_PATH, S_IRUSR | S_IWUSR) != 0) {
        fprintf(out, "[backend] chmod(%s) failed: %s\n",
                AUTH_SOCKET_PATH, strerror(errno));
        close_logged(server_fd, out, "server socket");
        unlink_socket_path(out);
        return -1;
    }

    if (listen(server_fd, BACKEND_LISTEN_BACKLOG) != 0) {
        fprintf(out, "[backend] listen() failed: %s\n", strerror(errno));
        close_logged(server_fd, out, "server socket");
        unlink_socket_path(out);
        return -1;
    }

    fprintf(out, "[backend] listening on %s\n", AUTH_SOCKET_PATH);
    return server_fd;
}

static int accept_one_client(int server_fd, FILE *out)
{
    int client_fd;

    for (;;) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd >= 0) {
            fputs("[backend] accepted one client connection\n", out);
            return client_fd;
        }

        if (errno == EINTR) {
            continue;
        }

        fprintf(out, "[backend] accept() failed: %s\n", strerror(errno));
        return -1;
    }
}

static int verify_peer_credentials(int client_fd, uid_t expected_uid,
                                   gid_t expected_gid, FILE *out)
{
    struct ucred peer;
    socklen_t peer_length = sizeof(peer);

    memset(&peer, 0, sizeof(peer));
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                   &peer, &peer_length) != 0) {
        fprintf(out, "[backend] getsockopt(SO_PEERCRED) failed: %s\n",
                strerror(errno));
        return -1;
    }

    fprintf(out, "[backend] peer PID=%ld UID=%lu GID=%lu\n",
            (long)peer.pid,
            (unsigned long)peer.uid,
            (unsigned long)peer.gid);

    if (peer_length != sizeof(peer) || peer.pid <= 0 ||
        peer.uid == (uid_t)-1 || peer.gid == (gid_t)-1) {
        fputs("[backend] rejected invalid peer credentials\n", out);
        return -1;
    }

    if (peer.uid != expected_uid || peer.gid != expected_gid) {
        fprintf(out,
                "[backend] rejected unexpected peer; expected UID=%lu GID=%lu\n",
                (unsigned long)expected_uid, (unsigned long)expected_gid);
        return -1;
    }

    fputs("[backend] peer credentials verified\n", out);
    return 0;
}

static int write_all(int fd, const void *buffer, size_t length, FILE *out)
{
    const unsigned char *cursor = (const unsigned char *)buffer;

    while (length > 0u) {
        ssize_t written = write(fd, cursor, length);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(out, "[backend] write() failed: %s\n", strerror(errno));
            return -1;
        }

        if (written == 0) {
            fputs("[backend] write() returned zero bytes\n", out);
            return -1;
        }

        cursor += (size_t)written;
        length -= (size_t)written;
    }

    return 0;
}

static int read_all(int fd, void *buffer, size_t length, FILE *out)
{
    unsigned char *cursor = (unsigned char *)buffer;

    while (length > 0u) {
        ssize_t received = read(fd, cursor, length);

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(out, "[backend] read() failed: %s\n", strerror(errno));
            return -1;
        }

        if (received == 0) {
            fputs("[backend] client closed before sending a complete request\n", out);
            return -1;
        }

        cursor += (size_t)received;
        length -= (size_t)received;
    }

    return 0;
}

static void set_response(AuthResponse *response, AuthResult result,
                         AuthErrorCode error_code, const char *message)
{
    memset(response, 0, sizeof(*response));
    response->version = AUTH_PROTOCOL_VERSION;
    response->result = (uint32_t)result;
    response->error_code = (uint32_t)error_code;
    snprintf(response->message, sizeof(response->message), "%s", message);
}

static int secure_field_equal(const char *left, const char *right, size_t length)
{
    unsigned char difference = 0u;
    size_t index;

    for (index = 0u; index < length; index++) {
        difference |= (unsigned char)left[index] ^ (unsigned char)right[index];
    }

    return difference == 0u;
}

static void process_request(const AuthRequest *request,
                            const DemoCredential *credential,
                            AuthResponse *response, FILE *out)
{
    int username_matches;
    int password_matches;

    if (request->version != AUTH_PROTOCOL_VERSION) {
        set_response(response, AUTH_RESULT_REJECTED,
                     AUTH_ERROR_UNSUPPORTED_VERSION,
                     "unsupported protocol version");
        fprintf(out, "[backend] rejected protocol version %u\n",
                (unsigned)request->version);
        return;
    }

    if (request->type != AUTH_REQUEST_VALIDATE) {
        set_response(response, AUTH_RESULT_REJECTED, AUTH_ERROR_BAD_REQUEST,
                     "unsupported authentication request type");
        fprintf(out, "[backend] rejected request type %u\n",
                (unsigned)request->type);
        return;
    }

    if (memchr(request->username, '\0', sizeof(request->username)) == NULL ||
        request->username[0] == '\0') {
        set_response(response, AUTH_RESULT_REJECTED, AUTH_ERROR_USERNAME_REQUIRED,
                     "a valid username is required");
        fputs("[backend] rejected request with invalid username\n", out);
        return;
    }

    if (memchr(request->password, '\0', sizeof(request->password)) == NULL ||
        request->password[0] == '\0') {
        set_response(response, AUTH_RESULT_REJECTED, AUTH_ERROR_PASSWORD_REQUIRED,
                     "a valid password is required");
        fputs("[backend] rejected request with invalid password\n", out);
        return;
    }

    username_matches = secure_field_equal(request->username,
                                          credential->username,
                                          sizeof(request->username));
    password_matches = secure_field_equal(request->password,
                                          credential->password,
                                          sizeof(request->password));

    if (!(username_matches & password_matches)) {
        set_response(response, AUTH_RESULT_INVALID_CREDENTIALS, AUTH_ERROR_NONE,
                     "invalid username or password");
        fprintf(out, "[backend] authentication rejected for %s\n",
                request->username);
        return;
    }

    set_response(response, AUTH_RESULT_SUCCESS, AUTH_ERROR_NONE,
                 "authentication successful");
    fprintf(out, "[backend] authentication successful for %s\n",
            request->username);
}

static int send_peer_rejection(int client_fd, FILE *out)
{
    AuthResponse response;

    set_response(&response, AUTH_RESULT_REJECTED, AUTH_ERROR_BAD_REQUEST,
                 "peer credentials rejected");
    return write_all(client_fd, &response, sizeof(response), out);
}

static int handle_client(int client_fd, const DemoCredential *credential,
                         FILE *out)
{
    AuthRequest request;
    AuthResponse response;
    int result = -1;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    if (read_all(client_fd, &request, sizeof(request), out) != 0) {
        goto cleanup;
    }

    process_request(&request, credential, &response, out);

    if (write_all(client_fd, &response, sizeof(response), out) != 0) {
        goto cleanup;
    }

    fprintf(out, "[backend] sent response: result=%u error=%u\n",
            (unsigned)response.result, (unsigned)response.error_code);
    result = 0;

cleanup:
    secure_clear(&request, sizeof(request));
    return result;
}

int main(void)
{
    FILE *log = stdout;
    char credential_path[PATH_MAX];
    DemoCredential credential;
    uid_t invoking_uid = getuid();
    gid_t invoking_gid = getgid();
    int server_fd = -1;
    int client_fd = -1;
    int exit_code = EXIT_FAILURE;

    memset(credential_path, 0, sizeof(credential_path));
    memset(&credential, 0, sizeof(credential));

    fputs("[backend] startup\n", log);
    log_uids(log, "startup");
    (void)log_proc_status_uid_lines(log, "startup");

    if (resolve_demo_credential_path(credential_path,
                                     sizeof(credential_path), log) != 0) {
        goto cleanup;
    }

    if (load_demo_credential(credential_path, &credential, log) != 0) {
        goto cleanup;
    }

    if (drop_privileges_permanently(invoking_uid, invoking_gid, log) != 0) {
        goto cleanup;
    }

    server_fd = create_server_socket(log);
    if (server_fd < 0) {
        goto cleanup;
    }

    client_fd = accept_one_client(server_fd, log);
    if (client_fd < 0) {
        goto cleanup;
    }

    if (verify_peer_credentials(client_fd, invoking_uid, invoking_gid, log) != 0) {
        (void)send_peer_rejection(client_fd, log);
        goto cleanup;
    }

    if (handle_client(client_fd, &credential, log) == 0) {
        exit_code = EXIT_SUCCESS;
    }

cleanup:
    close_logged(client_fd, log, "client socket");
    close_logged(server_fd, log, "server socket");
    if (server_fd >= 0) {
        unlink_socket_path(log);
    }
    secure_clear(&credential, sizeof(credential));
    secure_clear(credential_path, sizeof(credential_path));
    return exit_code;
}
