# minilink

minilink is a work-in-progress tactical datalink prototype for secure, point-to-point and relay-style message exchange over mutually authenticated TLS channels. The project is intended to explore a lightweight communication layer for local or lab-style networked operations, with an emphasis on simple message forwarding, identity handling, and server-side logging.

## What it is

At the moment, minilink provides a small experimental framework with:

- a TLS-based server that accepts client connections
- a TLS-based client that connects to the server
- basic multi-client message relay behavior
- simple client naming via `setname` and `getname`
- a server console with status and connection commands
- optional logfile generation for operational traceability

This is not yet a production tactical communications stack. It is a compact engineering prototype for testing concepts such as session establishment, message propagation, operator visibility, and secure transport.

## Current capabilities

### Server features

- binds to a configurable address
- accepts incoming TLS connections
- tracks connected peers
- relays messages from one connected client to other connected clients
- stores per-client names for display and lookup
- exposes a simple console for:
  - `status`
  - `connections`
  - `help`
  - `save_log`
  - `exit`

### Client features

- connects to the server over mutual TLS
- sends messages to the server
- receives relayed messages from other peers
- displays a `msg>` prompt for interactive use

## Project layout

- `src/main.rs` — entrypoint, configuration loading, and mode selection
- `src/network.rs` — TLS server/client implementation, message forwarding, name handling, console commands, and logging
- `test_conf.json` — example server configuration
- `test_conf_client.json` — example client configuration
- `certificate.der` and `identity.p12` — sample identity material used by the current test setup

## Prerequisites

You will need:

- Rust toolchain (stable)
- a working TLS certificate and private key in the formats expected by the app

The repository currently ships with example files for local testing, but these should be treated as placeholders for development and experimentation.

## Building

From the project root:

```bash
cargo build
```

## Running

The application expects three arguments:

```bash
cargo run -- <cfg_path> <der_path> <pkcs12_path>
```

### Server example

```bash
cargo run -- test_conf.json certificate.der identity.p12
```

### Client example

```bash
cargo run -- test_conf_client.json certificate.der identity.p12
```

## Configuration

The runtime configuration is loaded from JSON. A typical server config looks like this:

```json
{
  "mode": "server",
  "address": "127.0.0.1:8000",
  "blocked_addresses": ["127.0.0.2:8000"],
  "logfile_path": "minilink.log",
  "log": true,
  "domain": "localhost",
  "password": "your-password"
}
```

A typical client config looks like this:

```json
{
  "mode": "client",
  "address": "127.0.0.1:8000",
  "blocked_addresses": ["127.0.0.2:8000"],
  "logfile_path": "minilink.log",
  "log": true,
  "domain": "localhost",
  "password": "your-password",
  "entry_message": "CLIENT_CONNECTED"
}
```

## Messaging behavior

When one client sends a message, the server relays it to the other connected clients. The implementation also supports lightweight identity commands:

```text
setname Alice
getname Bob
```

These names are stored on the server and used in console and message presentation.

## Logging

If logging is enabled, minilink writes operational activity to the configured logfile path. The server console can also save the current logfile to a snapshot file using:

```text
save_log
```

## Development status

minilink is currently in an early prototype stage. The focus is on validating the core interaction model:

- secure transport
- message propagation
- operator console behavior
- identity tracking
- simple event logging

Future work may include:

- richer message formats
- better role and permission models
- more robust connection lifecycle handling
- packet framing and protocol versioning
- operational hardening for field use

## Notes

This repository is best viewed as a research and development sandbox for tactical datalink-style communication concepts. It is useful for local testing, protocol exploration, and understanding how a lightweight relay architecture might behave under simple TLS-backed messaging conditions.
