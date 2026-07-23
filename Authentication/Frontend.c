#define _POSIX_C_SOURCE 200809L

#include "auth_protocol.h"
#include "secure_memory.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>
#define FRONTEND_HAS_TERMIOS 1
#define FRONTEND_HAS_UNIX_SOCKET 1
#else
#define FRONTEND_HAS_TERMIOS 0
#define FRONTEND_HAS_UNIX_SOCKET 0
#endif

#define USERNAME_INPUT_BUFFER_SIZE (AUTH_USERNAME_MAX + 2u)
#define PASSWORD_INPUT_BUFFER_SIZE (AUTH_PASSWORD_MAX + 2u)

typedef struct TerminalEchoState {
#if FRONTEND_HAS_TERMIOS
    struct termios original;
#endif
    int restore_required;
} TerminalEchoState;

#if FRONTEND_HAS_UNIX_SOCKET
static volatile sig_atomic_t frontend_interrupted = 0;

static void handle_frontend_signal(int signal_number)
{
    (void)signal_number;
    frontend_interrupted = 1;
}

static int install_frontend_signal_handlers(void)
{
    struct sigaction termination_action;
    struct sigaction pipe_action;

    memset(&termination_action, 0, sizeof(termination_action));
    termination_action.sa_handler = handle_frontend_signal;
    sigemptyset(&termination_action.sa_mask);
    if (sigaction(SIGINT, &termination_action, NULL) != 0 ||
        sigaction(SIGTERM, &termination_action, NULL) != 0) {
        perror("sigaction");
        return -1;
    }

    memset(&pipe_action, 0, sizeof(pipe_action));
    pipe_action.sa_handler = SIG_IGN;
    sigemptyset(&pipe_action.sa_mask);
    if (sigaction(SIGPIPE, &pipe_action, NULL) != 0) {
        perror("sigaction");
        return -1;
    }

    return 0;
}
#endif

static void discard_remaining_input_line(void)
{
    int ch;

    while ((ch = getchar()) != '\n' && ch != EOF) {
    }
}

static int disable_terminal_echo(TerminalEchoState *state)
{
    state->restore_required = 0;

#if FRONTEND_HAS_TERMIOS
    if (!isatty(STDIN_FILENO)) {
        return 0;
    }

    if (tcgetattr(STDIN_FILENO, &state->original) != 0) {
        perror("tcgetattr");
        return -1;
    }

    struct termios hidden = state->original;
    hidden.c_lflag &= (tcflag_t)~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        perror("tcsetattr");
        return -1;
    }

    state->restore_required = 1;
    return 0;
#else
    fputs("Warning: hidden password input requires termios support.\n", stderr);
    return 0;
#endif
}

static int restore_terminal_echo(const TerminalEchoState *state)
{
#if FRONTEND_HAS_TERMIOS
    if (state->restore_required &&
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &state->original) != 0) {
        perror("tcsetattr");
        return -1;
    }
#else
    (void)state;
#endif

    return 0;
}

static int read_username(char *username, size_t username_size)
{
    char input[USERNAME_INPUT_BUFFER_SIZE];
    size_t newline_index;
    size_t input_length;

#if FRONTEND_HAS_UNIX_SOCKET
    if (frontend_interrupted) {
        fputs("Authentication input interrupted.\n", stderr);
        return -1;
    }
#endif

    printf("Username: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
#if FRONTEND_HAS_UNIX_SOCKET
        if (frontend_interrupted) {
            fputs("Authentication input interrupted.\n", stderr);
            return -1;
        }
#endif
        if (feof(stdin)) {
            fputs("No username provided.\n", stderr);
        } else {
            perror("fgets");
        }
        return -1;
    }

    newline_index = strcspn(input, "\n");
    if (input[newline_index] == '\n') {
        input[newline_index] = '\0';
    } else {
        discard_remaining_input_line();
        fprintf(stderr, "Username is too long. Maximum length is %u characters.\n",
                (unsigned)AUTH_USERNAME_MAX);
        return -1;
    }

    input_length = strlen(input);
    if (input_length == 0u) {
        fputs("Username must not be empty.\n", stderr);
        return -1;
    }

    if (input_length >= username_size) {
        fprintf(stderr, "Username is too long. Maximum length is %u characters.\n",
                (unsigned)AUTH_USERNAME_MAX);
        return -1;
    }

    memcpy(username, input, input_length + 1u);
    return 0;
}

static int read_password(char *password, size_t password_size)
{
    char input[PASSWORD_INPUT_BUFFER_SIZE];
    TerminalEchoState echo_state;
    size_t newline_index = 0u;
    size_t input_length;
    int read_failed = 0;
    int input_too_long = 0;

    memset(input, 0, sizeof(input));

#if FRONTEND_HAS_UNIX_SOCKET
    if (frontend_interrupted) {
        fputs("Password input interrupted.\n", stderr);
        return -1;
    }
#endif

    printf("Password: ");
    fflush(stdout);

    if (disable_terminal_echo(&echo_state) != 0) {
        secure_clear(input, sizeof(input));
        return -1;
    }

#if FRONTEND_HAS_UNIX_SOCKET
    if (frontend_interrupted) {
        (void)restore_terminal_echo(&echo_state);
        putchar('\n');
        fputs("Password input interrupted.\n", stderr);
        secure_clear(input, sizeof(input));
        return -1;
    }
#endif

    if (fgets(input, sizeof(input), stdin) == NULL) {
        read_failed = 1;
    } else {
        newline_index = strcspn(input, "\n");
        if (input[newline_index] == '\n') {
            input[newline_index] = '\0';
        } else {
            input_too_long = 1;
            discard_remaining_input_line();
        }
    }

    if (restore_terminal_echo(&echo_state) != 0) {
        secure_clear(input, sizeof(input));
        return -1;
    }

    putchar('\n');

#if FRONTEND_HAS_UNIX_SOCKET
    if (frontend_interrupted) {
        fputs("Password input interrupted.\n", stderr);
        secure_clear(input, sizeof(input));
        return -1;
    }
#endif

    if (read_failed) {
        if (feof(stdin)) {
            fputs("No password provided.\n", stderr);
        } else {
            perror("fgets");
        }
        secure_clear(input, sizeof(input));
        return -1;
    }

    if (input_too_long) {
        fprintf(stderr, "Password is too long. Maximum length is %u characters.\n",
                (unsigned)AUTH_PASSWORD_MAX);
        secure_clear(input, sizeof(input));
        return -1;
    }

    input_length = strlen(input);
    if (input_length == 0u) {
        fputs("Password must not be empty.\n", stderr);
        secure_clear(input, sizeof(input));
        return -1;
    }

    if (input_length >= password_size) {
        fprintf(stderr, "Password is too long. Maximum length is %u characters.\n",
                (unsigned)AUTH_PASSWORD_MAX);
        secure_clear(input, sizeof(input));
        return -1;
    }

    memcpy(password, input, input_length + 1u);
    secure_clear(input, sizeof(input));
    return 0;
}

#if FRONTEND_HAS_UNIX_SOCKET
static int write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = (const unsigned char *)buffer;

    while (length > 0u) {
        ssize_t written = write(fd, cursor, length);

        if (written < 0) {
            if (errno == EINTR) {
                if (frontend_interrupted) {
                    fputs("Authentication request interrupted.\n", stderr);
                    return -1;
                }
                continue;
            }
            perror("write");
            return -1;
        }

        if (written == 0) {
            fputs("Unable to send authentication request: write returned zero bytes.\n",
                  stderr);
            return -1;
        }

        cursor += (size_t)written;
        length -= (size_t)written;
    }

    return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = (unsigned char *)buffer;

    while (length > 0u) {
        ssize_t received = read(fd, cursor, length);

        if (received < 0) {
            if (errno == EINTR) {
                if (frontend_interrupted) {
                    fputs("Authentication response interrupted.\n", stderr);
                    return -1;
                }
                continue;
            }
            perror("read");
            return -1;
        }

        if (received == 0) {
            fputs("Backend closed the connection before sending a complete response.\n",
                  stderr);
            return -1;
        }

        cursor += (size_t)received;
        length -= (size_t)received;
    }

    return 0;
}

static int connect_to_backend(void)
{
    struct sockaddr_un address;
    size_t path_length;
    int socket_fd;

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;

    path_length = strlen(AUTH_SOCKET_PATH);
    if (path_length >= sizeof(address.sun_path)) {
        fprintf(stderr, "Backend socket path is too long: %s\n", AUTH_SOCKET_PATH);
        close(socket_fd);
        return -1;
    }

    memcpy(address.sun_path, AUTH_SOCKET_PATH, path_length + 1u);

    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fprintf(stderr, "Unable to connect to backend at %s: %s\n",
                AUTH_SOCKET_PATH, strerror(errno));
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

static int exchange_auth_request(AuthRequest *request, AuthResponse *response)
{
    int socket_fd;
    int result = -1;

    if (frontend_interrupted) {
        fputs("Authentication request cancelled.\n", stderr);
        secure_clear(request, sizeof(*request));
        return -1;
    }

    socket_fd = connect_to_backend();

    if (socket_fd < 0) {
        secure_clear(request, sizeof(*request));
        return -1;
    }

    if (write_all(socket_fd, request, sizeof(*request)) != 0) {
        secure_clear(request, sizeof(*request));
        goto cleanup;
    }
    secure_clear(request, sizeof(*request));

    if (read_all(socket_fd, response, sizeof(*response)) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    secure_clear(request, sizeof(*request));
    if (close(socket_fd) != 0) {
        perror("close");
        result = -1;
    }

    return result;
}
#endif

int main(void)
{
    AuthRequest request;
    AuthResponse response;
    int exit_code = EXIT_FAILURE;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    request.version = AUTH_PROTOCOL_VERSION;
    request.type = AUTH_REQUEST_VALIDATE;

#if FRONTEND_HAS_UNIX_SOCKET
    if (install_frontend_signal_handlers() != 0) {
        goto cleanup;
    }
#endif

    if (read_username(request.username, sizeof(request.username)) != 0) {
        goto cleanup;
    }

    if (read_password(request.password, sizeof(request.password)) != 0) {
        goto cleanup;
    }

#if FRONTEND_HAS_UNIX_SOCKET
    if (exchange_auth_request(&request, &response) == 0) {
        if (memchr(response.message, '\0', sizeof(response.message)) == NULL) {
            fputs("Backend returned a malformed response message.\n", stderr);
        } else if (response.version != AUTH_PROTOCOL_VERSION) {
            fprintf(stderr, "Unsupported backend protocol version: %u\n",
                    (unsigned)response.version);
        } else {
            if (response.result == AUTH_RESULT_SUCCESS) {
                printf("Authentication succeeded: %s (result=%u, error=%u)\n",
                       response.message,
                       (unsigned)response.result,
                       (unsigned)response.error_code);
                exit_code = EXIT_SUCCESS;
            } else {
                fprintf(stderr,
                        "Authentication failed: %s (result=%u, error=%u)\n",
                        response.message,
                        (unsigned)response.result,
                        (unsigned)response.error_code);
            }
        }
    }
#else
    fputs("UNIX domain sockets are not supported by this build.\n", stderr);
#endif

cleanup:
    secure_clear(&request, sizeof(request));
    secure_clear(&response, sizeof(response));
    return exit_code;
}
