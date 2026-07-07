#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
make task2
exec ./task2-sandbox/build/Sandbox ./task2-sandbox/build/normal_exit
