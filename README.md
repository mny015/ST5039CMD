# ST5039CMD CW1

This repository contains the practical work for ST5039CMD Programming and Operating Systems coursework CW1.

The repository is organized around two coursework tasks:

- `task1-auth/`: privilege-separated authentication with a frontend process, backend process, authentication IPC protocol, and secure memory clearing helpers.
- `task2-sandbox/`: user-space sandbox controller with monitoring, logging, and test binaries for process-control experiments.

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
|   |-- logger.c
|   |-- logger.h
|   |-- run_task2.sh
|   `-- test/
|       |-- normal_exit.c
|       |-- infinite_loop.c
|       |-- memory_hog.c
|       |-- sleep_long.c
|       `-- ignore_sigterm.c
`-- diagrams/
    |-- task1-architecture.png
    `-- task2-architecture.png
```

## Build

```sh
make task1
make task2
make clean
```

`make task1` builds the Task 1 frontend and backend programs. `make task2` builds the sandbox controller and its test binaries.

## Run Task 1

Build the two programs, then configure the backend as a set-user-ID root
executable for the privilege-drop demonstration. Perform this setup only in
the coursework Linux VM:

```sh
make task1
sudo chown root:root task1-auth/build/Backend
sudo chmod 4755 task1-auth/build/Backend
```

Start the backend in one terminal:

```sh
./task1-auth/build/Backend
```

Run the frontend in another terminal:

```sh
./task1-auth/build/Frontend
```

Alternatively, run the automated valid-login, wrong-password, and
unknown-user demonstration:

```sh
./task1-auth/run_task1.sh
```

The script prints the backend UID and `SO_PEERCRED` output for each case and
saves the backend logs under `task1-auth/build/`.

Use the fake credentials `demo_user` and `demo_password`. The backend loads
`credentials.demo`, permanently drops to the invoking user's UID, verifies the
client's kernel-reported UNIX socket credentials, and then validates the
structured authentication request. Do not store real passwords in the demo
credential file.

## Run Task 2

```sh
cd task2-sandbox
./run_task2.sh
```

The script builds Task 2 and supervises the `normal_exit` test binary with the
default five-second timeout. To exercise timeout termination and the SIGKILL
fallback directly, run:

```sh
./task2-sandbox/build/Sandbox --timeout 2 ./task2-sandbox/build/infinite_loop
./task2-sandbox/build/Sandbox --timeout 2 ./task2-sandbox/build/ignore_sigterm
```

The parent reports the child PID and final `waitpid()` status. A timeout is
requested by the monitor thread; the parent sends SIGTERM, waits one second,
and sends SIGKILL only if the child remains alive.
