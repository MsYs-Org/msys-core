# MSYS native runtime, phases 1 through 3

This directory contains three independently buildable C++20 migration steps:

- phase 1: the event reactor in `libmsys-reactor.a`;
- phase 2: the deliberately bounded `msysd-native-lite` process supervisor;
- phase 3: a bounded mIPC v0 broker integrated with native-lite readiness.

Native-lite can supervise a small, precompiled display/window/shell process
graph and expose the phase-3 lifecycle subset of mIPC, but it is not a drop-in
replacement for the Python reference supervisor. In particular, it has no
dynamic package, role, HAL, or update logic.

The implementation has no third-party dependencies. It uses Linux and libc
facilities directly:

- `epoll` for a single-threaded readiness loop;
- `timerfd` for monotonic one-shot and periodic timers;
- `signalfd` for synchronous signal delivery;
- `eventfd` for a thread-safe `request_stop()` wake-up;
- `pidfd_open` plus `waitid(P_PIDFD)` for race-resistant child identity and
  reaping on kernels that support them;
- a tested, per-known-pid `SIGCHLD` plus `waitid(P_PID)` fallback for older or
  pidfd-restricted kernels;
- `posix_spawn`, never a shell, for the safe launch path, with explicit fd
  close/allowlist actions generated from `/proc/self/fd`.

## Build and test

Run on Linux (WSL is sufficient for workstation testing):

```sh
make -C native
make -C native test
```

Both phase-1 test binaries compile with C++20, strict warnings, and `-Werror`:

- `reactor-unit-tests` covers epoll fd ownership, timerfd, signalfd, signal-mask
  restoration, callback-exception isolation across complete event batches,
  argument validation, and cross-thread eventfd wake-up;
- `reactor-integration-tests` launches real children, observes exit and signal
  status, audits `/proc/self/fd` inheritance, verifies process-group isolation,
  exact environments, and controlled PATH resolution, forces the old-kernel
  fallback, covers coalesced `SIGCHLD`, ESRCH/register-after-reap, and reports an
  accidental competing reaper without hanging.

The resulting libraries are `native/build/libmsys-reactor.a` and
`native/build/libmsys-mipc-broker.a`. Their public APIs are in
`include/msys/reactor.hpp` and `include/msys/mipc_broker.hpp`.

The phase-2 test set additionally covers strict plan parsing and file security,
dependency-ordered readiness, rejection of non-exact readiness records, reverse
shutdown, same-group descendant cleanup, restart generation/backoff, terminal
spawn failure, and an RSS regression guard. The native-lite binary is
`native/build/msysd-native-lite`.

The phase-3 tests cover strict bounded JSON parsing, runtime ownership, public
stream framing compatible with `msys-sdk` and `msys-tools`, private inherited
descriptor handshakes, peer identity and ACL hooks, lifecycle calls, the static
v2-plan role catalog (`preferred`, ready `active`, and candidate metadata),
protocol failure cleanup, deterministic backpressure, and an RSS regression
guard:

```sh
make -C native test-mipc
make -C native mipc-rss-test
```

## Native-lite runtime plan

Native-lite intentionally does not parse JSON on the target. On the development
machine, compile the closed JSON source schema into its bounded line protocol:

```sh
python3 native/scripts/compile_runtime_plan.py \
  native/examples/native-lite-plan.source.json \
  -o /tmp/msys-native-lite.plan

native/build/msysd-native-lite \
  --plan /tmp/msys-native-lite.plan \
  --check-plan
```

Edit the absolute executable paths in the example before running it. The JSON
schema identifier is `msys.native-lite-plan.source.v1`. Unknown and duplicate
fields are rejected. The compiler also validates bounds, unique ids, dependency
existence and cycles, then emits components in a deterministic topological
order. It uses no package lookup or shell expansion.

Each component supplies an absolute argv vector, optional environment overrides,
startup dependencies, a restart policy, a bounded exponential-backoff budget,
and one of three readiness modes:

- `exec`: ready immediately after `posix_spawn()` succeeds;
- `fd`: the child reads the decimal descriptor from `MSYS_READY_FD`, writes
  exactly `READY\n`, closes that descriptor, and remains in the foreground.
- `mipc-ready`: requires `--runtime-dir`; the child adopts the inherited
  `MSYS_CONTROL_FD`, sends an exact component/generation `hello`, receives
  `welcome`, then sends `ready`. Losing this private channel fails the running
  component generation.

The supervisor also sets `MSYS_COMPONENT_ID`, `MSYS_GENERATION`, and, when
enabled, `MSYS_RUNTIME_DIR`. A plan may not override these variables or the two
descriptor variables. Restart limits are total budgets
for one supervisor lifetime; phase 2 deliberately does not reset the budget
after a stable-running interval.

At runtime the compiled plan is opened with `O_NOFOLLOW`. It must be a regular
file, owned by the supervisor's effective uid, not group/world writable, and no
larger than 1 MiB. Run the bounded supervisor with:

```sh
native/build/msysd-native-lite \
  --plan /tmp/msys-native-lite.plan \
  --runtime-dir /tmp/msys-native-lite-runtime \
  --report-rss
```

## Phase-3 mIPC compatibility and scope

The public `control.sock` preserves the existing ABI: it is an
`AF_UNIX/SOCK_STREAM` socket carrying one UTF-8 JSON object per LF-terminated
line. The server sends the public `welcome` line immediately. Existing
`msys-sdk` public calls and `msys-tools.remote_ctl` therefore use the same wire
format. The socket is mode 0600 in an owner-only 0700 runtime directory.

Private `MSYS_CONTROL_FD` channels preserve the component ABI instead: they are
`AF_UNIX/SOCK_SEQPACKET`, with one UTF-8 JSON object per record and no newline.
The phase-3 parser accepts the current `hello`, `ready`, and `call` fields,
including `deadline_ms` and `idempotent`, with a 256 KiB record limit and strict
UTF-8/JSON validation. The older 40-byte binary header in `include/msys/mipc.h`
is a separate, currently unused experimental ABI; phase 3 does not put that
header in front of the production JSON envelope.

Native-lite exposes a deliberately static read-only role catalog through
`msys.core.list_roles`. The catalog is built only from the bounded v2 compiled
runtime plan: component `provide role` records create candidates, and the
profile's ordered `roles` entries determine `preferred`/`explicit` ordering.
Each response uses the existing public mIPC JSON ABI and returns `role`,
`exclusive`, `preferred`, `active`, `active_providers`, and candidate
`component`/`priority`/`exclusive`/`explicit`/`declared`/`state` fields. In
this static phase `active` is the first ready candidate in compiled order; it
is not a persistent Python-style role lease and never changes the plan.

The same bounded router can forward a call to an already-declared static
`role:<name>` or `interface:<name>` provider and expose `list_apps` and
`foreground_stack`, but it cannot dynamically select/reorder providers.
`select_role`, `reset_role`, `reload_registry`, and display migration return
`NATIVE_STATIC_CATALOG`. Dynamic manifests/packages, lease accounting for
multiple active non-exclusive providers, catalog reload, richer service
discovery, cancellation, and FD forwarding remain in the production Python
Core. Its offline plan has no dynamic permission catalog, so public control is
restricted to the supervisor euid and component-originated calls are denied by
default. The broker exposes an ACL hook for a later catalog-aware embedding.

SIGINT and SIGTERM trigger one-at-a-time shutdown in reverse actual start order.
Each component receives SIGTERM as a process group and, after `stop_grace_ms`,
SIGKILL. If the watched leader exits first, any remaining members of its process
group are killed before lifecycle processing continues. Components must not
daemonize or move descendants into another process group. A noncritical
dependency dying after dependents became ready does not retroactively stop those
dependents in this bounded phase.

To stage only the native-lite executable without selecting a host init system:

```sh
make -C native install-lite DESTDIR=/tmp/msys-stage PREFIX=/usr
```

The target runtime needs Linux, libc, the compiler's standard C++ runtime, and
`/proc`, but it needs no Python, JSON library, systemd, D-Bus, or additional
third-party library. `pidfd` is used when available and has a tested SIGCHLD
fallback. The example RSS limit of 64 MiB is a regression ceiling, not a
promised steady-state footprint.

## Signal and child ownership contract

Construct, run, and destroy a `Reactor` on the same thread, before creating any
other threads that might receive its watched signals. The constructor blocks
`SIGCHLD`; each `watch_signal()` blocks its signal in the owner thread and
updates the single signalfd. The original owner-thread mask is restored at
destruction. `request_stop()` is the sole cross-thread operation.
Destroying on a different thread is a contract violation and calls
`std::terminate()` rather than restoring the saved signal mask on the wrong
thread.

The reactor must be the exclusive reaper for every pid passed to
`watch_child()`. Direct children only are accepted. A competing reaper is
reported once as `ChildExitKind::lost` instead of silently wedging the event
loop. This includes registering a pid after another reaper has already removed
it: a handle is still returned and exactly one asynchronous `lost` callback is
queued. pidfd is preferred automatically. `PidfdPolicy::disabled` exists both
for old-kernel deployments and deterministic fallback tests.

`spawn_process()` restores the pre-reactor signal mask in the child, can supply
an exact environment, and creates a process group by default. It requires an
absolute executable path by default. Optional name lookup uses only non-empty,
absolute entries from the PATH belonging to the supplied child environment;
it never silently consults a different host PATH. Every open descriptor is
explicitly closed except `SpawnOptions::inherited_fds` (default `0,1,2`), and an
identity dup action makes an explicitly allowed CLOEXEC descriptor inheritable.
Because fd enumeration and `posix_spawn()` are a single-threaded ownership
operation, other threads must not mutate the process fd table concurrently.

Bare `Reactor` destruction deliberately does not kill watched processes.
Native-lite's `Supervisor` owns restart, grace-period, and process-group
escalation policy; cgroup and stronger descendant isolation remain outside this
phase.

## Callback failure semantics

Exceptions from fd, timer, signal, and child callbacks are isolated. The
reactor continues every other user callback already present in the same epoll
or signalfd batch and counts failed callbacks as dispatched. Failures retain
their callback kind, handle, and `std::exception_ptr`; the owner drains them in
dispatch order with `take_callback_failures()`. Reactor/syscall failures are not
user failures and still throw directly from `run_once()` or `run()`.

## Explicit migration boundary

These phases supply event/direct-child primitives plus the bounded offline-plan
supervisor described above. The following behavior remains in the tested Python
supervisor and must migrate in separate, contract-compatible steps:

- dynamic manifest/catalog discovery, roles, quarantine, display transactions,
  and the full component state machines;
- full catalog-aware mIPC routing, role/service calls, broadcasts,
  subscriptions, cancellation, and FD forwarding;
- package/install/update policy, release rollback, HAL selection, and UI policy;
- namespace, uid/gid, resource-limit, seccomp, cgroup, and filesystem isolation.

### Replacement gates

`msysd-native-lite` may become the production Core only after the native path
passes every gate below against the same contracts and fault cases as the
Python supervisor. A matching socket greeting or a smaller RSS number is not a
replacement criterion.

1. **Catalog and profile parity**
   - Strictly decode and validate `msys.manifest.v1` and `msys.profile.v1`,
     including closed fields, extensions, canonical package/component ids,
     dependency cycles, `requires`/`wants`/`after`, disabled roles, startup
     order, lifecycle/readiness modes, permissions, presentation metadata,
     locale state, and isolation declarations.
   - Merge generated fallback manifests, explicitly selected canonical
     manifests, and installed immutable versions package-atomically. A newer
     package that deletes a component must not leave the old component behind.
   - Resolve `@package` executable/cwd paths, trusted package roots, icons, and
     application presentation without accepting symlink or traversal escapes.

2. **Lifecycle and process parity**
   - Implement manual, session, background, and on-demand activation; exact
     generation/state reporting; exec, mIPC, and X11 readiness; ordered
     dependencies; graceful stop/escalation; restart budgets/backoff;
     quarantine and provider fallback; and deterministic shutdown.
   - Preserve private inherited control descriptors, readiness loss, pending
     call failure, concurrent start/stop fencing, on-demand idle reaping, low
     memory application reaping, foreground order, and transition events.
   - Reproduce component environment construction: selected display and locale,
     activation payloads, private HOME/XDG/TMP state, platform SDK boundaries,
     process credentials, namespaces, rlimits, no-new-privs, seccomp hooks, and
     process-group/descendant ownership.

3. **mIPC authorization and routing parity**
   - Keep the public newline JSON and private seqpacket JSON ABIs, bounded frame
     parsing, peer credentials, supervised-descendant attribution, call ids,
     deadlines, idempotence, typed errors, backpressure, and FD ownership.
   - Enforce manifest call/event ACLs for exact components, roles, interfaces,
     wildcard subscriptions, broadcasts, and direct interface-provider calls.
   - Preserve reentrant forwarding, cancellation, timeout distinction, provider
     disconnect/exit behavior, exact/prefix/global fan-out, and bounded
     subscription/pending-call state.

4. **Dynamic role, service, and activation parity**
   - Build role/interface/capability catalogs from the live package set;
     preserve profile order, manifest priority, disabled roles, exclusive and
     non-exclusive leases, multiple active providers, preferred overrides,
     persistent select/reset, generation release, and on-demand cold start.
   - Match `discover`, `list_roles`, `resolve_intent`, `activate`,
     `activate_role`, `list_apps`, `list_components`, `foreground_stack`,
     `start`, `stop`, and `broadcast`, including chooser/intent routing and
     stable window identity/activation payloads.

5. **Transactional package and update parity**
   - Match `preflight_registry`, `preflight_registry_remove`, and
     `reload_registry` over a prospective complete catalog before pointer
     commit. Validate cross-package dependencies, startup refs, roles, services,
     and removal restoration of built-in fallbacks.
   - Preserve changed critical-provider health gates, install transaction
     recovery after interruption, atomic live catalog swap, package-changed
     events, failed reload rollback, and the ordinary install/update agent role
     boundary. Core must not absorb downloader or signature policy.

6. **Display and hardware-role parity**
   - Keep HAL as replaceable role/interface providers rather than hard-coded
     device logic. Support dynamic selection and restart without embedding
     Wi-Fi, Bluetooth, CH347, HDMI, or SPI policy in Core.
   - Match display-output migration ids/status, planned/switching/succeeded/
     rolled-back events, old-output hold, inherited-display consumer suspend
     and ordered restart, preference/lease rollback, foreground restoration,
     outage recovery, and bounded X11 policy fallback semantics.

7. **Operational and compatibility parity**
   - Remain one foreground, non-daemonizing ordinary host service with exact
     runtime ownership/locking, control socket modes, signal handling, logs,
     status probes, current/previous release rollback, and no systemd or D-Bus
     dependency. It must never become PID 1 or reap unrelated host children.
   - Pass differential Python/native protocol and state traces, crash/timeout/
     power-loss fault injection, package upgrade/removal rollback, display
     migration rollback, ACL negative tests, long-running RSS/FD/thread bounds,
     and current SDK/tools compatibility before a selectable cutover exists.

### Staged route after native-lite

- **Phase 4 — native catalog library:** implement strict manifest/profile and
  installed-registry models behind an offline `--check-catalog` tool. Compare
  normalized catalogs byte-for-byte with Python; do not supervise production
  components yet.
- **Phase 5 — lifecycle shadow:** feed the real catalog into the native state
  machine and replay recorded spawn/readiness/exit events without owning the
  live processes. Gate on identical states, generations, fallback, and errors.
- **Phase 6 — broker shadow:** mirror sanitized mIPC calls/events to the native
  router read-only and diff responses, authorization decisions, role/service
  resolution, deadline behavior, and bounded resource accounting.
- **Phase 7 — transactional subsystems:** add registry preflight/reload and
  display migration as separately fault-injected native modules. Keep Python in
  control until install rollback and visual-session rollback suites are
  identical.
- **Phase 8 — opt-in canary:** make native Core an explicit profile/release
  choice with the existing host-service `current`/`previous` health rollback.
  Exercise kiosk first, then mobile/desktop dynamic packages. It becomes the
  default only after all seven gates pass; native-lite itself is never silently
  promoted.

The native runtime is **not PID 1**. It does not reap unrelated host children,
mount filesystems, populate `/dev`, configure ttys, manage seats, replace the
host init, or depend on systemd or D-Bus. MSYS remains an ordinary host service,
and adopting this library later must preserve that boundary.
