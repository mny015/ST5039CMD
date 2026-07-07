#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
make task1
exec ./task1-auth/build/Frontend
