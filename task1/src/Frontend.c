#include "auth_protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USERNAME_INPUT_BUFFER_SIZE (AUTH_USERNAME_MAX + 2u)

static void discard_remaining_input_line(void)
{
    int ch;

    while ((ch = getchar()) != '\n' && ch != EOF) {
    }
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

int main(void)
{
    AuthRequest request;

    memset(&request, 0, sizeof(request));
    request.version = AUTH_PROTOCOL_VERSION;
    request.type = AUTH_REQUEST_VALIDATE;

    if (read_username(request.username, sizeof(request.username)) != 0) {
        return EXIT_FAILURE;
    }

    printf("Username accepted for validation request: %s\n", request.username);
    puts("Socket IPC is not implemented yet.");

    return EXIT_SUCCESS;
}
