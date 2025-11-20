# GEMINI.md

## Project Overview

This is a Tauri-based desktop application for managing system proxy settings. It provides a simple user interface to set, reset, and restore the system's HTTP proxy. The application is built with a Rust backend and a plain HTML/JavaScript frontend.

The core logic is handled by the `sysproxy-rs` crate, which is included as a local dependency. The application is cross-platform, with specific implementations for Windows, macOS, and Linux to handle system proxy settings and to listen for changes to those settings.

## Building and Running

The project uses `pnpm` as the package manager for the frontend and `cargo` for the Rust backend.

### Prerequisites

*   Node.js and pnpm
*   Rust and Cargo
*   Tauri development environment setup

### Development

To run the application in development mode, use the following command:

```bash
pnpm install
pnpm dev
```

### Production

To build the application for production, use the following command:

```bash
pnpm build
```

## Project Structure

*   `src/index.html`: The main HTML file for the user interface. It contains the UI layout and the JavaScript logic for interacting with the backend.
*   `src-tauri/src/main.rs`: The main Rust file for the backend. It defines the Tauri commands for managing the system proxy and handles the application lifecycle.
*   `src-tauri/Cargo.toml`: The Cargo manifest for the Rust backend. It defines the dependencies, including `tauri` and the local `sysproxy` crate.
*   `src-tauri/sysproxy/`: The local `sysproxy-rs` crate, which provides the core functionality for interacting with system proxy settings.
*   `package.json`: The Node.js manifest for the frontend. It defines the dependencies and the scripts for running and building the application.
*   `tauri.conf.json`: The Tauri configuration file.

## Development Conventions

*   The frontend is written in plain HTML and JavaScript, with no framework.
*   The backend is written in Rust.
*   Communication between the frontend and backend is done through Tauri's command and event system.
*   The application is designed to restore the original proxy settings when it exits.
