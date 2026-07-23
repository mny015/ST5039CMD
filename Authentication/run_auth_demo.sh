#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

AUTH_SOCKET_PATH=/tmp/st5039cmd_auth.sock
BACKEND=./Authentication/build/Backend
FRONTEND=./Authentication/build/Frontend
LOG_DIR=./Authentication/build
backend_pid=

cleanup()
{
    if [ -n "$backend_pid" ] && kill -0 "$backend_pid" 2>/dev/null; then
        kill -TERM "$backend_pid" 2>/dev/null || true
        wait "$backend_pid" 2>/dev/null || true
    fi
}

trap cleanup EXIT
trap 'exit 130' HUP INT TERM

wait_for_socket()
{
    log_file=$1
    attempts=0

    while [ ! -S "$AUTH_SOCKET_PATH" ] ||
          ! grep -q '\[backend\] listening on' "$log_file"; do
        if ! kill -0 "$backend_pid" 2>/dev/null; then
            set +e
            wait "$backend_pid"
            backend_status=$?
            set -e
            backend_pid=
            cat "$log_file"
            printf 'Backend exited before creating its socket (status %s).\n' \
                "$backend_status" >&2
            return 1
        fi

        attempts=$((attempts + 1))
        if [ "$attempts" -ge 50 ]; then
            printf 'Timed out waiting for backend socket %s.\n' \
                "$AUTH_SOCKET_PATH" >&2
            return 1
        fi
        sleep 0.1
    done
}

run_case()
{
    case_name=$1
    username=$2
    password=$3
    expected_frontend_status=$4
    log_file="$LOG_DIR/auth-$case_name.log"

    printf '\n=== %s ===\n' "$case_name"
    rm -f "$log_file"
    "$BACKEND" >"$log_file" 2>&1 &
    backend_pid=$!

    wait_for_socket "$log_file"

    set +e
    printf '%s\n%s\n' "$username" "$password" | "$FRONTEND"
    frontend_status=$?
    wait "$backend_pid"
    backend_status=$?
    set -e
    backend_pid=

    printf '%s\n' '--- backend UID and peer credential output ---'
    cat "$log_file"

    if [ "$frontend_status" -ne "$expected_frontend_status" ]; then
        printf 'Unexpected frontend status: got %s, expected %s.\n' \
            "$frontend_status" "$expected_frontend_status" >&2
        return 1
    fi

    if [ "$backend_status" -ne 0 ]; then
        printf 'Backend failed with status %s.\n' "$backend_status" >&2
        return 1
    fi
}

make task1

run_case valid-login demo_user demo_password 0
run_case wrong-password demo_user wrong_password 1
run_case unknown-user unknown_user demo_password 1

printf '\nAuthentication demonstration completed successfully.\n'
printf 'Backend logs are available in %s/auth-*.log\n' "$LOG_DIR"
