# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A minimal Tauri 2 demo application for setting/resetting system proxy. The frontend is a simple HTML page with two inputs for proxy configuration. The backend reuses the `sysproxy-rs` library to handle system proxy operations across platforms (Windows, macOS, Linux).

## Development Commands

```bash
# Install dependencies
pnpm install

# Run in development mode
pnpm dev

# Build production bundle
pnpm build

# Run Tauri CLI directly
pnpm tauri [command]
```

### Rust Backend Commands

```bash
cd src-tauri

# Check Rust code
cargo check

# Build Rust backend only
cargo build

# Run tests
cargo test

# Run clippy (note: this project has strict linting rules)
cargo clippy
```

**Note on Windows**: If `set_system_proxy` fails, place the compiled `sysproxy.exe` from sysproxy-rs at the same level as `src-tauri` and run with administrator privileges.

## Architecture

### Frontend (`src/index.html`)

Single HTML file with inline JavaScript that:
- Provides two input fields (host and port) for proxy configuration
- Uses `window.__TAURI__.core.invoke` to call backend commands
- Dynamically loads the Tauri API bridge (handles different Tauri module paths)
- Listens for `proxy-changed` events to detect system proxy changes
- Shows saved original proxy configuration and current system proxy

### Backend (`src-tauri/src/main.rs`)

Tauri 2 application with five main commands:

1. **`set_system_proxy(host, port)`**: Applies system proxy
   - Saves original proxy configuration on first use (in `SAVED_PROXY` global state)
   - Disables PAC (auto proxy) and enables manual proxy
   - Uses platform-specific bypass lists via `DEFAULT_BYPASS` constant

2. **`reset_system_proxy()`**: Disables both system proxy and auto proxy

3. **`restore_system_proxy()`**: Restores the original proxy configuration that was saved before first use

4. **`get_saved_proxy()`**: Returns the saved original proxy configuration

5. **`get_current_proxy()`**: Returns current system proxy state

### System Proxy Monitoring

The application monitors system proxy changes outside the app and emits `proxy-changed` events:

- **Windows**: Uses Registry change notifications on `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`
- **macOS**: Uses SystemConfiguration framework's dynamic store with patterns for network proxy changes
- **Linux**: Watches the dconf configuration file (`~/.config/dconf/user`) using the notify crate

### Sysproxy Library (`src-tauri/sysproxy/`)

A vendored copy of the `sysproxy-rs` library with platform-specific implementations:

- **Core types**: `Sysproxy` (manual proxy) and `Autoproxy` (PAC/auto proxy)
- **Platform modules**: `windows.rs`, `macos.rs`, `linux.rs` handle OS-specific proxy operations
- **Features**: Supports `guard` feature for proxy monitoring (using tokio)

#### Key Platform Differences

- **Bypass lists**: Each platform uses different formats for proxy bypass rules (see `DEFAULT_BYPASS` constants in main.rs)
- **Windows**: Uses Registry APIs
- **macOS**: Uses SystemConfiguration framework with network interface detection
- **Linux**: Uses gsettings/dconf (requires GNOME/similar desktop environment)

### Exit Behavior

The app calls `restore_system_proxy()` on exit (via `RunEvent::Exit` and `RunEvent::ExitRequested`) to restore the original proxy configuration.

## Tauri Configuration

- **Config file**: `src-tauri/tauri.conf.json`
- **Frontend source**: `../src` (single HTML file, no build step)
- **Global Tauri**: Enabled (`withGlobalTauri: true`), allowing access via `window.__TAURI__`
- **Window**: 800x800, resizable

## Code Style Notes

The sysproxy crate has strict clippy linting rules:
- Denies most `correctness` and `suspicious` lints
- Warns on `unwrap_used` and `expect_used`
- Denies mutex/async anti-patterns
- See `src-tauri/sysproxy/Cargo.toml` for full lint configuration
