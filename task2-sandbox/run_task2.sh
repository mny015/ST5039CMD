#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

SANDBOX=./task2-sandbox/build/Sandbox
TEST_DIR=./task2-sandbox/build

run_case()
{
    case_name=$1
    expected_status=$2
    shift 2

    printf '\n=== %s ===\n' "$case_name"
    set +e
    "$SANDBOX" "$@"
    actual_status=$?
    set -e

    if [ "$actual_status" -ne "$expected_status" ]; then
        printf 'Unexpected sandbox status: got %s, expected %s.\n' \
            "$actual_status" "$expected_status" >&2
        return 1
    fi
}

process_is_running()
{
    process_pid=$1
    process_state=

    if [ ! -r "/proc/$process_pid/stat" ]; then
        return 1
    fi
    process_state=$(awk '{ print $3 }' "/proc/$process_pid/stat" \
        2>/dev/null) || return 1
    [ "$process_state" != "Z" ]
}

wait_for_child_pid()
{
    log_file=$1
    attempts=0

    while [ "$attempts" -lt 100 ]; do
        child_pid=$(sed -n 's/.*leader PID=\([0-9][0-9]*\).*/\1/p' \
            "$log_file" | head -n 1)
        if [ -n "$child_pid" ]; then
            printf '%s\n' "$child_pid"
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.05
    done
    return 1
}

run_controller_signal_case()
{
    case_name=$1
    controller_signal=$2
    log_file=$(mktemp)

    printf '\n=== %s ===\n' "$case_name"
    "$SANDBOX" --timeout 30 "$TEST_DIR/sleep_long" >"$log_file" 2>&1 &
    controller_pid=$!
    child_pid=$(wait_for_child_pid "$log_file") || {
        cat "$log_file" >&2
        kill -KILL "$controller_pid" 2>/dev/null || true
        rm -f "$log_file"
        return 1
    }

    kill "-$controller_signal" "$controller_pid"
    set +e
    wait "$controller_pid"
    controller_status=$?
    set -e

    attempts=0
    while process_is_running "$child_pid" && [ "$attempts" -lt 100 ]; do
        attempts=$((attempts + 1))
        sleep 0.05
    done
    if process_is_running "$child_pid"; then
        cat "$log_file" >&2
        printf 'Child PID %s survived controller signal %s.\n' \
            "$child_pid" "$controller_signal" >&2
        rm -f "$log_file"
        return 1
    fi
    if [ "$controller_signal" = "TERM" ] &&
       ! grep -q 'operator signal' "$log_file"; then
        cat "$log_file" >&2
        printf 'Controller did not report operator-signal cleanup.\n' >&2
        rm -f "$log_file"
        return 1
    fi
    if [ "$controller_status" -eq 0 ]; then
        cat "$log_file" >&2
        printf 'Controller unexpectedly reported success after signal.\n' >&2
        rm -f "$log_file"
        return 1
    fi
    cat "$log_file"
    rm -f "$log_file"
}

make task2

run_case normal-exit 0 \
    --timeout 3 "$TEST_DIR/normal_exit"
run_case timeout-kill 1 \
    --timeout 1 "$TEST_DIR/sleep_long"
run_case memory-limit 1 \
    --timeout 10 --memory-kb 16384 "$TEST_DIR/memory_hog"
run_case descendant-memory-limit 1 \
    --timeout 10 --memory-kb 24576 "$TEST_DIR/memory_fork_hog"
run_case cpu-monitoring 1 \
    --timeout 2 "$TEST_DIR/infinite_loop"
run_case sigterm-sigkill-fallback 1 \
    --timeout 1 "$TEST_DIR/ignore_sigterm"
run_case process-tree-escape 1 \
    --timeout 1 "$TEST_DIR/fork_escape"
run_case network-denial 0 \
    --timeout 3 "$TEST_DIR/network_attempt"
run_case filesystem-denial 0 \
    --timeout 3 "$TEST_DIR/filesystem_attempt"

exec 9<README.md
SECRET_TEST_TOKEN=must-not-leak run_case environment-and-fd-isolation 0 \
    --timeout 3 "$TEST_DIR/environment_fds"
exec 9<&-

run_controller_signal_case operator-signal-cleanup TERM
run_controller_signal_case parent-death-signal KILL

printf '\nTask 2 demonstration completed successfully.\n'
