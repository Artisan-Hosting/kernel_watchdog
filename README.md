# Artisan Watchdog Kernel Components

This directory contains the Linux kernel pieces that back the Artisan watchdog
runtime. The kernel module exposes a character device that user space uses to
register a monitored process and deliver signed heartbeat messages. When the
heartbeats stop or fail validation, the module escalates to a user-mode helper
that writes a persistent trip record to pstore/ramoops and, in production
builds, requests an emergency reboot.

## Directory Layout

- `driver/` – Out-of-tree kernel module sources (`awdog.c`, `awdog.h`,
  `Makefile`).
- `userland/` - Saver helper source (`awdog-saver.c`, `Makefile`) installed as
  `/sbin/awdog-saver`.

## Build and Install

```
make -C driver          # build awdog.ko against the running kernel
sudo insmod driver/awdog.ko
sudo rmmod awdog        # unload when finished
```

The module registers `/dev/awdog` and requires `CAP_SYS_ADMIN` to access.

Build the saver helper:

```
make -C userland
make -C userland test             # run userland helper tests
sudo make -C userland install     # installs /sbin/awdog-saver
```

Helper invocation shape used by the kernel:

```
/sbin/awdog-saver --phase <phase> --reason <reason> --raw-line "<kernel log line>"
```

### Dummy/Test Build

The driver Makefile also supports a non-destructive test build:

```
make -C driver all_dummy      # builds awdog_dummy.ko
sudo make -C driver install_dummy
```

`all_dummy` compiles the module with `-DAWDOG_TEST_MODE=1` and emits
`driver/awdog_dummy.ko`. In this mode, trip handling still invokes
`/sbin/awdog-saver` to persist trip records, but suppresses reboot.

## Automate ramoops Reservation

The saver helper writes trip records to `/dev/pmsg0`, so production setups
should reserve persistent RAM for pstore/ramoops at boot.

Use the helper script to auto-discover a suitable top-level `System RAM` range
from `/proc/iomem`, generate kernel args, and optionally apply GRUB changes:

```
./scripts/configure_ramoops_grub.sh --dry-run
./scripts/configure_ramoops_grub.sh --size-m 4 --dry-run
sudo ./scripts/configure_ramoops_grub.sh --size-m 2 --apply
```

Flags:

- `--size-m N`: reserve `N` MiB (default `2`).
- `--dry-run`: discovery + generated args only (default mode).
- `--apply`: writes `/etc/default/grub.d/40-awdog-ramoops.cfg`, rebuilds GRUB
  config, then requires a reboot.

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
  - Production build:
    - `awdog_trip_now()` invokes `/sbin/awdog-saver` with
      `phase/reason/raw_line` metadata to persist a trip record into
      `/dev/pmsg0` (picked up by pstore ramoops after reboot).
    - The reboot path emits an additional `reboot_requested` trip record and
      then calls `emergency_restart()`.
  - Dummy/test build (`AWDOG_TEST_MODE`):
    - `awdog_trip_now()` emits a `test_mode_trip` record through
      `/sbin/awdog-saver`.
    - Reboot is suppressed.
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

If the heartbeat stream stops or fails integrity checks, the module trips
through `awdog_trip_now()` and invokes `/sbin/awdog-saver`. The helper writes a
JSON `TripRecordMessage` to `/dev/pmsg0` with this shape:

- `ingested_at`: Unix timestamp when the helper emitted the record.
- `source`: source tag (default `awdog-live-trip`).
- `phase`: trip classifier (`tamper_tripped`, `reboot_requested`,
  `heartbeat_rejected`, `test_mode_trip`, or caller-provided structured value).
- `reason`: parsed trip reason.
- `raw_line`: full kernel-log-style line for this event.
- `attributes`: extra parsed key/value pairs, including structured
  `AWDOG_TRIP key=value` tokens.

For local testing without real pstore, set `AWDOG_PMSG_PATH=/tmp/<file>` before
running `awdog-saver` to write records into a regular file.

Any consumer that wants to observe or override these actions should hook into
`/sbin/awdog-saver` or adjust `awdog_run_soscall()` during integration.
