# ST5039CMD Coursework CW1

This repository contains the practical work for ST5039CMD Programming and Operating Systems coursework CW1.

The coursework is split into two implementation-driven tasks:

- Task 1: a privilege-separated authentication service that uses separate frontend and backend processes, secure local IPC, privilege dropping, runtime UID checks, and secure handling of password data.
- Task 2: a user-space sandbox controller that starts untrusted binaries as child processes, monitors them externally, uses concurrent monitoring threads, and enforces termination policies with operating system signals.

## Repository Structure

| Path | Purpose |
| --- | --- |
| `task1/src/` | Task 1 C source code for the frontend, backend, IPC protocol, and secure memory helpers. |
| `task1/data/` | Task 1 local data files, test inputs, or credential fixtures used by the implementation. |
| `task1/evidence/` | Task 1 build logs, runtime traces, UID checks, socket checks, and memory-clearing evidence. |
| `task2/src/` | Task 2 C source code for the sandbox controller and monitoring state. |
| `task2/test-binaries/` | Test programs used as untrusted binaries for sandbox demonstrations. |
| `task2/evidence/` | Task 2 build logs, monitoring logs, resource usage logs, and termination evidence. |
| `docs/` | Coursework notes, diagrams, requirements mapping, and written analysis. |
| `docs/diagrams/` | Process, IPC, privilege, and sandbox monitoring diagrams. |
| `scripts/` | Helper scripts for building, running demonstrations, and collecting evidence. |

## Planned Build

The root `Makefile` provides top-level targets for the coursework:

```sh
make task1
make task2
make evidence
make clean
```

At this stage the targets are placeholders. As the C implementations are added, `make task1` will build the Task 1 authentication programs, and `make task2` will build the Task 2 sandbox controller and test binaries.

## Planned Task 1 Run

Task 1 will demonstrate two independent executables:

```sh
make task1
./task1/build/Frontend
```

The frontend will collect authentication input and communicate with the backend over a local UNIX domain socket. The backend will perform validation, drop privileges permanently, and record evidence showing UID state, IPC behavior, rejected invalid requests, and secure password-buffer clearing.

## Planned Task 2 Run

Task 2 will demonstrate a sandbox controller supervising untrusted binaries:

```sh
make task2
./task2/build/Sandbox ./task2/build/cpu_spin
```

The parent sandbox process will start the untrusted binary with `fork()` and `execve()`, monitor time and resource usage from the outside, coordinate monitoring threads, and terminate the child with signals when policy limits are exceeded.

## Evidence

Evidence files will be collected under `task1/evidence/` and `task2/evidence/`. These files are intended to support the coursework report by showing actual build output, process behavior, privilege changes, IPC traces, resource monitoring, and termination logs.
