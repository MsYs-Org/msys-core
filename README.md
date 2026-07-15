# msys-core

Current source version: `0.1.20`.

Version 0.1.20 presents supervised entries with Core's localized component
name instead of the often-identical Linux `comm` value, filters non-userspace
kernel threads, and orders optional system results by known RSS descending
then PID so the bounded list remains useful on a small board.

Version 0.1.19 adds the bounded, read-only `msys.core.list_processes` process
inventory described below. It reuses Core's live component generations and
reads optional host-process metadata directly from `/proc`; it starts no
helper and has no systemd, D-Bus, or `ps` dependency.

`msys-core` contains the MSYS supervisor and broker. It is intentionally
self-contained: no systemd, no D-Bus, no logind, no polkit, no udev API.

The current implementation is a runnable Python reference supervisor. It exists
so the lifecycle, mIPC behavior, install/update hooks, and UI providers can be
tested immediately. The native C++ core will preserve the same contract.

## Run

```sh
python -m msys_core.msysd \
  --foreground \
  --config examples/config \
  --manifest ../msys-shell-native/manifest.json \
  --manifest ../msys-shell-pyside/manifest.json \
  --manifest ../msys-x11-session/manifest.json \
  --manifest ../msys-hal/manifest.json \
  --runtime-dir run \
  --profile mobile-spi
```

On Windows development shells the inherited socket FD path is not available in
the same way as Linux. The target runtime is Linux.

`--manifest` selects a package's canonical source-tree manifest and may be
repeated. Its complete package replaces the same package in the config fallback,
so removed components cannot linger. Installed registry packages apply the same
package-atomic rule and take precedence over development manifests.

The runtime directory has process ownership, not just a socket filename.
`msysd` holds an advisory `flock` on `.msysd.lock` for its complete lifetime;
a second supervisor for the same runtime exits instead of unlinking the live
`control.sock`. After a crashed owner releases the kernel lock, the next owner
may safely remove a stale socket and start normally.

## Responsibilities

- Load package manifests and profile role preferences.
- Start `session` and `background` components.
- Activate `on-demand` providers for role/interface calls.
- Supervise processes without daemonizing.
- Broker mIPC messages and events.
- Enforce manifest `mipc.call:*` and `mipc.event:*` ACLs on authenticated
  inherited component channels before routing or fan-out.
- Fan out exact, prefix-wildcard, and global event subscriptions with bounded
  per-component subscription state.
- Discover capabilities and route calls to roles, interfaces, or exact
  components, waking on-demand providers as needed.
- Track role leases and provider generations.
- Apply crash backoff and provider fallback.
- Expose install/update agents as normal background components.
- Start a replaceable HAL manager while keeping each hardware-domain provider
  independently discoverable and on demand.
- Publish foreground lifecycle transition events for a replaceable animation
  presenter without making presentation part of process supervision.
- Preflight prospective installed catalogs and health-check changed critical
  background/selected-role providers before an installer transaction is
  finalized.
- Preflight package removal against the complete remaining dependency, startup,
  role, and service catalogs before an uninstall moves registry pointers.

## Optional on-demand idle reclamation

An `on-demand` component can declare `idle_timeout_ms` from `1000` through
`86400000`. Without it, activation remains resident exactly as before. With it,
Core arms the timer after readiness, cancels it before every forwarded RPC, and
starts a fresh full interval only after the last concurrent call completes or
times out. Expiry follows ordinary graceful component stop and is fenced to the
captured instance generation, so stale timers cannot terminate a replacement.

The field is rejected for `manual`, `background`, and `session` components.
Idle tasks are component-owned and are cancelled on explicit stop, process
exit, registry replacement, and daemon shutdown.

## Role-based window activation

`msys.core.activate_role({"role":"launcher"})` resolves the active/preferred
provider from the live role registry, ensures that provider is ready, and asks
the selected window-manager to activate the provider using its manifest
identity and title. The response names the actual provider and generation.
Home paths use this API and contain no reference-launcher package id or title.

## Transactional registry reload

The install/update agents use three typed core methods:

- `preflight_registry({"package":...,"path":...})` overlays the immutable
  candidate on all built-in and currently installed packages, validates every
  cross-package `requires` edge/cycle, and constructs prospective role and
  service catalogs without changing the live catalog.
- `preflight_registry_remove({"package":...})` removes the installed package
  only in a prospective view, restores any built-in fallback, and rejects lost
  dependencies, profile startup jobs, or enabled roles before commit.
- `reload_registry({"verify_health":true})` retains the original additive API:
  it atomically swaps the live catalog, restarts changed eager components, and
  requires changed critical background and selected role providers to reach
  their declared readiness state.
- Install/update transactions additionally pass
  `transaction={"schema":"msys.catalog-transaction.v1","package":...,`
  `"version":...,"path":...,"removed":false}`. Core independently matches the
  committed registry and manifest identity, snapshots affected live manual
  components, replaces their processes, and proves that each resumed instance
  belongs to the new catalog at a generation above the old high-water mark.
  A stale ready process therefore cannot satisfy the gate. A failed switch
  returns the saved manual set so the restored version can resume it; a normal
  rollback uses the same mechanism. The successful reply adds a transaction
  proof without changing legacy reply fields.

Failures return `CATALOG_PREFLIGHT_FAILED`, `CATALOG_RELOAD_FAILED`, or
`CATALOG_HEALTH_FAILED`. The installer keeps its rollback-biased transaction
journal until the reload/health response succeeds. A journal left in
`health_pending` is interpreted as the restore registry during the next msysd
startup, so an interrupted update cannot make startup parse the unverified
catalog.

Successful per-call forward traces are quiet by default. Set
`MSYS_DEBUG_IPC=1` to print them; timeouts, failed providers, and other errors
remain visible without debug logging.

Reference profiles include adaptive `mobile-spi`, gesture
`mobile-spi-pill`, UI-free single-app `kiosk-spi`, and panel-style
`desktop-spi`. Equivalent `mobile-hdmi` and `desktop-hdmi` profiles select the
canonical X11 session's HDMI output without hard-coding `DISPLAY` into the
profile. `disabled_roles` makes omitted kiosk jobs stay unstarted instead of
silently selecting a discovered fallback provider.

The mobile and desktop profiles consolidate `launcher`, `system-chrome`,
`navigation-bar`, `task-switcher`, and `notification-presenter` into the one C
component `org.msys.shell.native:desktop-shell`. It is listed first for each
role and appears once in profile startup, so the former PySide launcher,
chrome, and navigation interpreters stay dormant. Their providers remain later
candidates for explicit fallback. PySide roles not implemented by the native
phase (`transition-presenter`, `notification-center`, and `chooser`) remain
lazy and are activated only by role calls; input method is likewise lazy.
Kiosk keeps HAL available to its single application and does not add native or
PySide shell UI.

All six reference profiles likewise select
`org.msys.hal.linux:native-manager` as the sole resident HAL manager. The
Python `org.msys.hal.linux:manager` stays second in the role candidate list and
is on-demand, so it remains a compatibility fallback without consuming idle
memory. This applies to kiosk as well as interactive profiles. The generated
HAL development fallback resolves its native executable at
`/opt/msys-dev/msys-hal/files/bin/msys-hal-native`, rather than treating the
Core manifest directory as the package root.

The same profiles enable a bounded low-memory reclaim policy for small boards.
Core reads Linux `MemAvailable` directly every two seconds. Below 48 MiB it
stops at most one oldest background ordinary application per poll, after a
15-second minimum lifetime. The current foreground application, display,
window policy, Shell, HAL, system roles, and non-manual services are never
candidates. The policy adds no daemon or external command and is configured by
the closed `settings.memory_reclaim` object in each profile.

The generated host-service launcher also fixes glibc's Core-only
`MALLOC_TRIM_THRESHOLD_` at 256 KiB unless an operator overrides it. glibc
consumes that value while the isolated interpreter starts; `msysd.main()` then
removes the variable before any component environment is constructed, so this
is not an allocator policy imposed on applications or replaceable providers.
On the 2026-07-13 OpenStick AArch64 audit, loading the complete formal catalog
and completing one real `xdpyinfo` readiness probe produced a median
`Pss_Anon` of 18,284 KiB without the fixed threshold and 15,668 KiB after the
same threshold was consumed and removed, a 2,616 KiB reduction. Samples were
fresh, unswapped processes using the same runtime and `MALLOC_ARENA_MAX=2`.
`python -S` was within 48 KiB of baseline, while `PYTHONMALLOC=malloc` increased
private anonymous memory by about 4.2 MiB; neither is enabled.

## Read-only process inventory

`msys.core.list_processes({})` returns Core itself plus live supervised MSYS
components whose manifest declares no X11/Wayland/window/overlay surface.
This default path is small and does not enumerate unrelated Linux processes.
Each result has the same closed fields; Core uses `source: "msys-core"`,
`component: "msys.core"`, `name: "MSYS Core"`, and
`lifecycle: "supervisor"`. Other managed names use the same localized
component presentation as `list_components`:

```json
{
  "pid": 123,
  "ppid": 1,
  "uid": 0,
  "name": "msys-hal-native",
  "state": "sleeping",
  "rss_kib": 2048,
  "source": "msys-supervisor",
  "msys_owned": true,
  "component": "org.msys.hal.linux:native-manager",
  "component_state": "ready",
  "runtime": "native",
  "lifecycle": "background",
  "generation": 1
}
```

`include_system` opts into a direct procfs snapshot of non-MSYS processes:

```json
{"include_system": true, "limit": 64}
```

The system `limit` defaults to 64 and is restricted to `1..128`; managed
headless results are independently capped at 128. Top-level
`managed_truncated` and `system_truncated` fields make either bound explicit.
System entries use `source: "procfs"`, `msys_owned: false`, and null MSYS-only
fields. Core excludes itself, every supervised leader, and descendants that
share a supervised process group or session. Kernel threads parented by
`kthreadd` with no userspace RSS are omitted. Enumeration retains at most the
requested number of proc records in memory, prioritizes known RSS values in
descending order with PID as the stable tie-breaker, never returns command
lines or environment values, and invokes no external command.

The checked-in `examples/config/manifests/shell-native.json` is a generated
development fallback. It preserves the canonical package semantics while
rewriting the executable to
`/opt/msys-dev/msys-shell-native/bin/msys-shell-native`. Production packages
retain canonical `@package` resolution inside the immutable installed root.

All reference profiles select
`org.msys.x11.session:window-policy` for both window-policy roles. The selected
`display-output` starts and reaches readiness before that independent session
policy, and the policy starts before any application or shell window. Profiles
do not encode a board-specific `DISPLAY`: at component spawn, Core uses the
active display provider (or the profile-selected provider before a lease is
active), reading `DISPLAY_ID` and then legacy `DISPLAY`. A component's own
`DISPLAY` is the final explicit override. If no display provider exports either
value, an inherited/profile value remains compatible and `:0` is the final X11
fallback.

Changing the exclusive `display-output` role is a visual-session transaction,
not a plain role lease update. Core returns a migration id before it can stop
the requesting UI, publishes `msys.display.migration` phases `planned`,
`switching`, and `succeeded`, and keeps the old output alive until the new
provider and every running X11 consumer whose display is `inherit` have reached
readiness. A failed switch restores the previous role lease and preference,
restarts attempted consumers on the old display, preserves foreground order,
and publishes `rolled-back` with a structured error and rollback health. The
`display_migration_status` method returns the active, requested, or latest
migration record. During ordered recovery, an already-ready current-generation
consumer remains callable; the outage fence still blocks every new,
handshaking, exited, or stale generation until its recovery turn.

CH347 USB/sink faults are retried inside the long-lived display provider, so
Xorg `:24` and its clients remain untouched. If the provider itself exits, its
X stack is not adopted by the next generation: Core treats that as a lost
display session but recreates only inherited `background`/`session` surfaces
such as window policy and system chrome. Manual applications are closed and
are never deceptively reopened. After output recovery Core publishes
`msys.display.output_recovered` (`msys.display-output-recovered.v1`) with the
fault class, failed/recovery generations, `applications_reopened: false`, the
restarted system UI, dropped applications, and any recovery failures. Explicit
role changes, DEBUG/rotation restarts, and catalog transactions remain full
visual-session migrations with their existing rollback behavior.

For native `window-manager.close_active` and `window-manager.back` calls, Core
publishes the current foreground generation's `closing` transition before
forwarding the call. This preserves an exit-mask animation when the native
policy terminates the process before replying; the instance flag shared with
`stop_component` keeps the event idempotent. Background system overlays are not
foreground applications and never receive this transition.

The independent policy is always the primary control path. If it is absent or
returns a definite error, Core may execute a bounded X11 command as a last-resort
control API fallback on the dynamically resolved session display; it does not
claim the WM selection or run a competing event loop. Successful fallback
responses contain `fallback: true` (also repeated in an object payload) and emit
an explicit diagnostic log. Calls whose non-idempotent outcome is unknown are
never replayed by the fallback.

Profiles are validated as the closed, language-neutral `msys.profile.v1`
contract before any component is started. The loader rejects unsafe profile
names, filename/id mismatches, unknown non-`x-` fields, duplicate component or
role entries, conflicting enabled/disabled roles, malformed component refs,
and invalid environment, state, isolation-helper, or settings values. Optional
provider refs remain valid even when that package is not currently installed.

### Session locale contract

The supervisor treats `MSYS_LOCALE`, `LANG`, and every `LC_*` value as selected
visual-session state rather than per-package configuration.  It captures those
values after the trusted profile `env` has been applied, restores them after a
component manifest's `env`, and then applies ordinary private HOME/XDG/Python
application isolation.  A valid POSIX locale such as `zh_CN.UTF-8` is also
published as canonical `MSYS_LOCALE=zh-CN`, so SDK, Qt/Tk/Electron, and native
applications can agree without a locale daemon, systemd, or D-Bus.  Add
`MSYS_LOCALE` to a profile's `env` when an operator needs an explicit
deployment-wide MSYS language selection; `C`/`POSIX` retains the
catalog-default behavior.

`list_apps` and `list_components` also apply that session locale to the
package/component `x-msys-i18n` presentation declaration. Catalogs are strict
UTF-8 package-relative files, component declarations override package
declarations, and missing or invalid resources fall back to the manifest's
static `name`/`summary`. Core keeps a small bounded positive/negative cache, so
a polling launcher does not repeatedly open immutable package resources.

## Optional process isolation prototype

MSYS still defaults to compatibility: a component without an `isolation`
declaration receives no namespace, prctl, rlimit, or seccomp policy. Installed
packages continue to receive their private HOME/XDG/TMP environment as before;
that environment separation alone is not a security sandbox.

A component can opt into one of the built-in execution profiles:

```json
{
  "id": "worker",
  "runtime": "native",
  "exec": ["@package/files/bin/worker"],
  "lifecycle": "background",
  "restart": "on-failure",
  "isolation": {
    "profile": "namespaced",
    "failure": "fail-closed",
    "rlimits": {
      "nofile": {"soft": 256, "hard": 256},
      "as": 536870912,
      "core": 0
    }
  }
}
```

`@package/` execution paths are strict POSIX-relative package references:
empty, dot, parent, absolute, backslash, and package-escaping paths are
rejected. When `argv[0]` uses `@package/`, it must resolve to a regular,
executable, non-symlink file immediately before spawn. Host commands such as
`python` and `bash`, absolute host commands, and ordinary relative argv values
retain their normal lookup behavior.

For compatibility with the strict v1 extension mechanism, core also accepts
the same value under `x-msys-isolation`. Declaring both is an error. The
first-class contracts schema should add `isolation` before packages using that
spelling are distributed through a schema-validating installer.

Profiles are:

- `none`: no kernel restrictions. This is the undeclared default.
- `baseline`: `PR_SET_NO_NEW_PRIVS`, non-dumpable, core dumps disabled, and a
  1024 descriptor limit.
- `namespaced`: baseline plus user, mount, IPC, UTS, and network namespaces,
  and conservative process/descriptor limits.
- `custom`: only explicitly listed settings.

`namespaces` can contain `user`, `mount`, `ipc`, `uts`, and `network`.
`pid` is intentionally rejected: entering a PID namespace correctly requires
a double fork or a dedicated launcher helper, which this prototype does not
pretend to perform. Supported rlimits are detected from Python/Linux and can
include `as`, `core`, `cpu`, `data`, `fsize`, `memlock`, `nofile`, `nproc`, and
`stack`. An integer sets both soft and hard values; an object can set them
individually.

Every opt-in declaration defaults to `fail-closed` if it omits `failure`:

- `fail-closed`: a statically absent feature or a child-side application error
  aborts the spawn. It is never silently weakened.
- `best-effort`: statically absent features are listed in the launch report;
  child-side failures are written as `msys-isolation: best-effort skipped ...`
  before execution continues. A partially entered user namespace remains
  fatal because that transition cannot be rolled back safely.

The supervisor exposes its non-mutating probe through
`msys.core.isolation_capabilities`. The result deliberately says
`permission_probe: deferred-to-child`: `/proc/self/ns/*` and libc symbol
presence do not prove that this kernel permits a particular `unshare(2)` call.
Each running component's `list_components` entry and
`MSYS_ISOLATION_JSON` environment describe the requested/effective static
plan, degradation, and failure policy.

### Optional seccomp helper

Core has no libseccomp or Python package dependency and does not claim an
in-process seccomp filter. An operator may configure a trusted executable at
profile key `isolation.seccomp_helper` (or `MSYS_SECCOMP_HELPER`). A component
then requests:

```json
"isolation": {
  "profile": "baseline",
  "failure": "fail-closed",
  "seccomp": {"mode": "helper", "profile": "desktop-v1"}
}
```

Core invokes the helper without a shell as:

```text
HELPER --profile desktop-v1 -- ORIGINAL_ARGV...
```

The trusted helper is responsible for installing and verifying its filter and
then `exec`ing the original argv while preserving inherited mIPC descriptors.
Missing helpers follow `fail-closed`/`best-effort` exactly. Merely naming a
helper profile is not evidence that a filter is secure.

### Security boundary

This is a useful optional containment layer, not a complete application
sandbox. In particular:

- mount namespaces make mount changes private but do not hide the host rootfs;
- UID 0 on the current OpenStick host still needs a deliberately designed
  filesystem/UID policy, even when mapped into a user namespace;
- mIPC call/event permissions are enforced on inherited component channels,
  and public peers attributable by `SO_PEERCRED` PID/process group/session are
  checked as that component; only unmatched root peers are operator admins;
- same-UID/root code can create a new session, re-parent helpers, inspect other
  processes, or attack outside mIPC, so strong hostile-component separation
  still requires distinct UIDs/namespaces, capability removal, and a protected
  non-forgeable launch label such as a cgroup;
- other manifest permissions are not converted to syscall or filesystem
  allowlists;
- cgroups, Landlock, capability bounding, PID namespaces, and seccomp policy
  generation are not implemented;
- the Python reference supervisor applies child restrictions with
  `preexec_fn`; a native launcher is preferred for a hardened multi-threaded
  production supervisor.

For those reasons reports use the literal boundary marker
`partial-not-a-filesystem-sandbox` rather than claiming full isolation.
