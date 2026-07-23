#ifndef TASK1_AUTH_PROTOCOL_H
#define TASK1_AUTH_PROTOCOL_H

#include <stdint.h>

#define AUTH_SOCKET_PATH "/tmp/st5039cmd_auth.sock"
#define AUTH_PROTOCOL_VERSION 1u

#define AUTH_USERNAME_MAX 64u
#define AUTH_PASSWORD_MAX 128u
#define AUTH_RESPONSE_MESSAGE_MAX 128u

typedef enum AuthRequestType {
    AUTH_REQUEST_VALIDATE = 1
} AuthRequestType;

typedef enum AuthResult {
    AUTH_RESULT_SUCCESS = 0,
    AUTH_RESULT_INVALID_CREDENTIALS = 1,
    AUTH_RESULT_REJECTED = 2,
    AUTH_RESULT_ERROR = 3
} AuthResult;

typedef enum AuthErrorCode {
    AUTH_ERROR_NONE = 0,
    AUTH_ERROR_BAD_REQUEST = 1,
    AUTH_ERROR_UNSUPPORTED_VERSION = 2,
    AUTH_ERROR_USERNAME_REQUIRED = 3,
    AUTH_ERROR_USERNAME_TOO_LONG = 4,
    AUTH_ERROR_PASSWORD_REQUIRED = 5,
    AUTH_ERROR_PASSWORD_TOO_LONG = 6,
    AUTH_ERROR_IPC_FAILURE = 7,
    AUTH_ERROR_PRIVILEGE_DROP_FAILED = 8,
    AUTH_ERROR_INTERNAL = 9
} AuthErrorCode;

typedef struct AuthRequest {
    uint32_t version;
    uint32_t type;
    char username[AUTH_USERNAME_MAX + 1u];
    char password[AUTH_PASSWORD_MAX + 1u];
} AuthRequest;

typedef struct AuthResponse {
    uint32_t version;
    uint32_t result;
    uint32_t error_code;
    char message[AUTH_RESPONSE_MESSAGE_MAX + 1u];
} AuthResponse;

#endif
