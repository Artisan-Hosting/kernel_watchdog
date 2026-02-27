# Artisan Watchdog Kernel Components

This directory contains the Linux kernel pieces that back the Artisan watchdog
runtime. The kernel module exposes a character device that user space uses to
register a monitored process and deliver signed heartbeat messages. When the
heartbeats stop or fail validation, the module escalates to a user-mode helper
and, ultimately, a system reboot.

## Directory Layout

- `driver/` – Out-of-tree kernel module sources (`awdog.c`, `awdog.h`,
  `Makefile`).
- `init.sh` – Convenience script for inserting/removing the module on dev
  systems.

## Build and Install

```
make -C driver          # build awdog.ko against the running kernel
sudo insmod driver/awdog.ko
sudo rmmod awdog        # unload when finished
```

The module registers `/dev/awdog` and requires `CAP_SYS_ADMIN` to access.

### Dummy/Test Build

The driver Makefile also supports a non-destructive test build:

```
make -C driver all_dummy      # builds awdog_dummy.ko
sudo make -C driver install_dummy
```

`all_dummy` compiles the module with `-DAWDOG_TEST_MODE=1` and emits
`driver/awdog_dummy.ko`. In this mode, trip handling logs the reason and runs
the ko-test helper (`/bin/echo`) instead of invoking `/sbin/awdog-saver` and
`emergency_restart()`.

## Module Behaviour

* State lives in a single global context (`struct awdog_ctx`). Registration
  locks a mutex, copies the caller-provided key/session data, seeds the timers,
  and opens the watchdog window.
* Heartbeats are fixed-size blobs (`struct awdog_hb`) written to the character
  device. Each heartbeat:
  - Must carry a strictly-increasing monotonic nonce.
  - Is authenticated with HMAC-SHA256 (`crypto_shash`).
  - Includes a monotonic and real-time timestamp so we can log latency
    information.
* Trigger logic is simplified around a single trip path (`awdog_trip_now()`):
  - Timeout path: timer callback queues one work item (`awdog_queue_trip()` ->
    `awdog_trip_workfn()`) and the worker calls `awdog_trip_now(reason)`.
  - Verification-failure path: `awdog_write()` calls `awdog_trip_now("verify-failed")`
    directly after dropping the mutex.
  - Production build: `awdog_trip_now()` runs `/sbin/awdog-saver` and then
    `emergency_restart()`.
  - Dummy/test build (`AWDOG_TEST_MODE`): `awdog_trip_now()` suppresses saver
    and reboot, and calls the ko-test helper instead.
* Unregister/module exit still flush pending trip work with `cancel_work_sync()`
  to guarantee teardown does not race the deferred timeout trip worker.

## User-Space Contract

`awdog.h` doubles as the UAPI header. User programs are expected to:

1. Open `/dev/awdog` with `O_WRONLY` (must be `CAP_SYS_ADMIN`).
2. Issue `AWDOG_IOCTL_REGISTER` with a populated `struct awdog_register` that
   includes:
   - Target PID and executable fingerprint (monitored binary identity).
   - Shared secret (`key`) for HMAC.
   - Heartbeat period/timeout (milliseconds).
   - Session identifier and protocol version.
3. Periodically write heartbeats (exactly `sizeof(struct awdog_hb)`) containing
   the updated nonce, timestamps, and computed HMAC.
4. On shutdown, send `AWDOG_IOCTL_UNREG` and close the file descriptor.

If the heartbeat stream stops or fails integrity checks, the module logs the
reason and trips through `awdog_trip_now()`: production builds run the saver
helper and reboot, while `AWDOG_TEST_MODE` builds only run the ko-test helper.
Any consumer that wants to observe or override these actions should hook into
the user-mode binaries referenced in `awdog_run_soscall()` or adjust them
during integration.
