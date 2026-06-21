# wl-container

Creates a [Wayland security context][secctx] via `wp_security_context_manager_v1`.

[secctx]: https://gitlab.freedesktop.org/wayland/wayland-protocols/-/blob/main/staging/security-context/security-context-v1.xml

## Building

**Debian dependencies:**

    apt install libwayland-dev libclang-dev wayland-protocols

Then:

    cargo build --release

The binary has no Rust runtime dependencies. It links dynamically to `libwayland-client.so.0`.

## How it works

The caller provides a listening socket via `--socket-fd` or `--socket-path`. The program connects to the Wayland compositor, binds `wp_security_context_manager_v1`, and calls `create_listener` to register the socket as a security context. The compositor then accepts connections on that socket restricted to the security context's sandbox parameters (`--sandbox-engine`, `--app-id`, `--instance-id`).

## Usage

```
wl-container -s FD [-e ENGINE] [-a APP_ID] [-i INSTANCE] [-c FD] [-r FD]
wl-container -S PATH [-e ENGINE] [-a APP_ID] [-i INSTANCE] [-c FD] [-r FD]
```

- `-s`/`--socket-fd FD` — listen socket fd
- `-S`/`--socket-path PATH` — listen socket path
- `-e`/`--sandbox-engine ENGINE` — engine identifier
- `-a`/`--app-id APP_ID` — app identifier
- `-i`/`--instance-id INSTANCE` — instance identifier
- `-c`/`--close-fd FD` — stop listening when this fd closes
- `-r`/`--ready-fd FD` — notify readiness on this fd
- `-h`/`--help` — show help

Without `--close-fd` the process stays alive until killed.

