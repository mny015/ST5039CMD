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

make task2

run_case normal-exit 0 \
    --timeout 3 "$TEST_DIR/normal_exit"
run_case timeout-kill 1 \
    --timeout 1 "$TEST_DIR/sleep_long"
run_case memory-limit 1 \
    --timeout 10 --memory-kb 16384 "$TEST_DIR/memory_hog"
run_case cpu-monitoring 1 \
    --timeout 2 "$TEST_DIR/infinite_loop"
run_case sigterm-sigkill-fallback 1 \
    --timeout 1 "$TEST_DIR/ignore_sigterm"

printf '\nTask 2 demonstration completed successfully.\n'
