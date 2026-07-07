#include "auth_protocol.h"
#include "secure_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <termios.h>
#include <unistd.h>
#define FRONTEND_HAS_TERMIOS 1
#else
#define FRONTEND_HAS_TERMIOS 0
#endif

#define USERNAME_INPUT_BUFFER_SIZE (AUTH_USERNAME_MAX + 2u)
#define PASSWORD_INPUT_BUFFER_SIZE (AUTH_PASSWORD_MAX + 2u)

typedef struct TerminalEchoState {
#if FRONTEND_HAS_TERMIOS
    struct termios original;
#endif
    int restore_required;
} TerminalEchoState;

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

    printf("Username: ");
    fflush(stdout);

    if (fgets(input, sizeof(input), stdin) == NULL) {
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

    printf("Password: ");
    fflush(stdout);

    if (disable_terminal_echo(&echo_state) != 0) {
        secure_clear(input, sizeof(input));
        return -1;
    }

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

int main(void)
{
    AuthRequest request;

    memset(&request, 0, sizeof(request));
    request.version = AUTH_PROTOCOL_VERSION;
    request.type = AUTH_REQUEST_VALIDATE;

    if (read_username(request.username, sizeof(request.username)) != 0) {
        return EXIT_FAILURE;
    }

    if (read_password(request.password, sizeof(request.password)) != 0) {
        secure_clear(&request, sizeof(request));
        return EXIT_FAILURE;
    }

    printf("Credentials accepted for validation request: %s\n", request.username);
    puts("Socket IPC is not implemented yet.");

    secure_clear(&request, sizeof(request));
    return EXIT_SUCCESS;
}
