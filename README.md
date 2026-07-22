# ST5039CMD CW1

This repository contains the implementation for ST5039CMD Programming and
Operating Systems coursework CW1. It has two Linux-focused programs:

- **Task 1:** a privilege-separated authentication frontend and backend that
  communicate through a structured UNIX domain socket protocol.
- **Task 2:** a sandbox controller that supervises a complete process tree and
  enforces timeout and memory policies from parent-owned monitor threads.

## Requirements

Build and run the coursework in the coursework Linux VM or another Linux
environment with:

- GCC or a compatible C11 compiler
- GNU Make
- POSIX shell utilities
- POSIX threads and the Linux `/proc` filesystem

Task 1 also uses Linux `SO_PEERCRED` and `setresuid()`/`setresgid()`. Task 2
uses `/proc/<pid>/status` and `/proc/<pid>/stat`. These programs are therefore
not intended to run natively on Windows.

## Repository Structure

```text
ST5039CMD-CW1/
|-- README.md
|-- Makefile
|-- .gitignore
|-- task1-auth/
|   |-- Frontend.c
|   |-- Backend.c
|   |-- auth_protocol.h
|   |-- secure_memory.c
|   |-- secure_memory.h
|   |-- credentials.demo
|   `-- run_task1.sh
|-- task2-sandbox/
|   |-- Sandbox.c
|   |-- monitor.c
|   |-- monitor.h
|   |-- process_tree.c
|   |-- process_tree.h
|   |-- logger.c
|   |-- logger.h
|   |-- run_task2.sh
|   `-- test/
|       |-- normal_exit.c
|       |-- infinite_loop.c
|       |-- memory_hog.c
|       |-- sleep_long.c
|       |-- ignore_sigterm.c
|       `-- fork_escape.c
`-- diagrams/
    |-- task1-architecture.png
    `-- task2-architecture.png
```

Build output is generated under `task1-auth/build/` and
`task2-sandbox/build/`. These directories are ignored by Git.

## Build

Run all commands from the repository root:

```sh
make task1
make task2
```

Useful targets:

| Target | Purpose |
|---|---|
| `make task1` | Build `Frontend` and `Backend` |
| `make task2` | Build `Sandbox`, all test binaries, and verify the run scripts |
| `make task2-tests` | Build only the Task 2 test binaries |
| `make task1-demo` | Build and run the complete Task 1 demonstration |
| `make task2-demo` | Build and run the complete Task 2 demonstration |
| `make evidence` | Show where demonstration evidence is collected |
| `make clean` | Remove both generated `build/` directories |

To rebuild from a clean state:

```sh
make clean
make task1 task2
```

## Task 1: Authentication

The frontend reads a bounded username with `fgets()`, disables terminal echo
while reading the password, and sends an `AuthRequest` structure over
`/tmp/st5039cmd_auth.sock`. The backend verifies the client's kernel-reported
PID, UID, and GID with `SO_PEERCRED`, validates the request, checks the fake
demo credential, and returns an `AuthResponse`. Sensitive buffers are cleared
before exit.

The backend demonstrates a permanent privilege drop with `setresgid()` and
`setresuid()`. To show an elevated-to-unprivileged transition, configure the
already-built backend in the coursework Linux VM:

```sh
make task1
sudo chown root:root task1-auth/build/Backend
sudo chmod 4755 task1-auth/build/Backend
```

Only use this set-user-ID setup in the isolated coursework environment.

### Automated Run

```sh
./task1-auth/run_task1.sh
```

The script runs three cases: valid login, wrong password, and unknown user. It
prints UID and peer-credential information and stores backend logs in
`task1-auth/build/task1-*.log`.

The committed fake login is:

```text
Username: demo_user
Password: demo_password
```

Do not put real credentials in `credentials.demo`.

### Manual Run

Start the backend in one terminal:

```sh
./task1-auth/build/Backend
```

Then run the frontend in another terminal:

```sh
./task1-auth/build/Frontend
```

The backend handles one authentication connection and then exits. Start it
again before each additional manual login attempt.

## Task 2: Sandbox Controller

The sandbox controller forks and executes a target binary in a dedicated
process group, registers itself as a Linux child subreaper, and supervises the
entire descendant tree with `waitpid()` and `/proc` ancestry checks. Timeout,
memory, and CPU monitor threads aggregate observations across that tree and
communicate through mutex-protected shared state. When a limit is exceeded,
the parent sends `SIGTERM`, waits one second, and escalates every surviving
descendant to `SIGKILL`. A mutex-protected logger keeps concurrent output
readable.

### Automated Run

```sh
./task2-sandbox/run_task2.sh
```

The script demonstrates:

- normal child exit
- timeout termination
- memory-limit termination
- CPU usage monitoring
- `SIGTERM` to `SIGKILL` escalation
- detached-descendant detection after the original leader exits

Normal exit returns status `0`. Cases terminated by sandbox policy return a
non-zero status, which the demonstration script checks automatically.

### Manual Runs

The command format is:

```text
Sandbox [--timeout SECONDS] [--memory-kb KILOBYTES] <target-binary> [args...]
```

Examples from the repository root:

```sh
./task2-sandbox/build/Sandbox --timeout 3 \
  ./task2-sandbox/build/normal_exit

./task2-sandbox/build/Sandbox --timeout 2 \
  ./task2-sandbox/build/infinite_loop

./task2-sandbox/build/Sandbox --timeout 10 --memory-kb 16384 \
  ./task2-sandbox/build/memory_hog

./task2-sandbox/build/Sandbox --timeout 2 \
  ./task2-sandbox/build/ignore_sigterm
```

If `--timeout` is omitted, the default is five seconds. Memory enforcement is
disabled unless `--memory-kb` is provided; CPU monitoring always reports usage
changes.

## Architecture Diagrams

- `diagrams/task1-architecture.png` shows the frontend, socket protocol,
  credential source, backend validation, and privilege boundary.
- `diagrams/task2-architecture.png` shows the parent controller, shared state,
  monitor threads, child process, signal policy, and logger.
