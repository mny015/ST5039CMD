#include "auth_protocol.h"
#include "secure_memory.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define PROC_STATUS_PATH "/proc/self/status"
#define PROC_STATUS_LINE_MAX 256u
#define BACKEND_LISTEN_BACKLOG 4

static void log_startup_uids(FILE *out)
{
    uid_t real_uid = getuid();
    uid_t effective_uid = geteuid();

    fprintf(out, "[backend] getuid(): %lu\n", (unsigned long)real_uid);
    fprintf(out, "[backend] geteuid(): %lu\n", (unsigned long)effective_uid);
}

static int log_proc_status_uid_lines(FILE *out)
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
            fprintf(out, "[backend] /proc/self/status %s", line);
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
            fprintf(out, "[backend] accepted one client connection\n");
            return client_fd;
        }

        if (errno == EINTR) {
            continue;
        }

        fprintf(out, "[backend] accept() failed: %s\n", strerror(errno));
        return -1;
    }
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

static void process_request(const AuthRequest *request, AuthResponse *response,
                            FILE *out)
{
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

    set_response(response, AUTH_RESULT_SUCCESS, AUTH_ERROR_NONE,
                 "authentication request received");
    fprintf(out, "[backend] accepted authentication request for %s\n",
            request->username);
}

static int handle_client(int client_fd, FILE *out)
{
    AuthRequest request;
    AuthResponse response;
    int result = -1;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    if (read_all(client_fd, &request, sizeof(request), out) != 0) {
        goto cleanup;
    }

    process_request(&request, &response, out);

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
    int server_fd;
    int client_fd;
    int exit_code = EXIT_FAILURE;

    fputs("[backend] startup\n", log);
    log_startup_uids(log);
    (void)log_proc_status_uid_lines(log);

    server_fd = create_server_socket(log);
    if (server_fd < 0) {
        return EXIT_FAILURE;
    }

    client_fd = accept_one_client(server_fd, log);
    if (client_fd >= 0) {
        if (handle_client(client_fd, log) == 0) {
            exit_code = EXIT_SUCCESS;
        }
        close_logged(client_fd, log, "client socket");
    }

    close_logged(server_fd, log, "server socket");
    unlink_socket_path(log);

    return exit_code;
}
