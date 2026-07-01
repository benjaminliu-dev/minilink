# minilink

minilink is a tactical datalink prototype for secure, point-to-point and relay-style message exchange over mutually authenticated TLS channels. It is intended as a lightweight experimental framework for local or lab-style networked operations, with a focus on simple message forwarding, identity handling, and server-side logging.

## Overview

minilink supports two modes:

- server: accepts incoming TLS clients, tracks connected peers, relays messages, and exposes a small operator console
- client: connects to the server over mutual TLS, sends messages, and receives relayed traffic from other peers

It is a prototype and not a production communications stack.

## Features

### Server

- configurable listen address
- accepts TLS client connections
- tracks peers and client names
- relays messages to other connected clients
- operator console with commands:
  - `status`
  - `connections`
  - `help`
  - `save_log`
  - `exit`

### Client

- mutual TLS connection to the server
- interactive `msg>` prompt
- relays messages exchanged with other peers
- supports lightweight identity setting via `setname`

## Project layout

- `src/main.rs` — application entrypoint, configuration loading, and mode selection
- `src/network.rs` — TLS server/client implementation, relay logic, command handling, and logging
- `test_conf.json` — example server configuration
- `test_conf_client.json` — example client configuration
- `certificate.der` and `identity.p12` — sample identity material for local testing

## Prerequisites

- Rust toolchain (stable)
- a compatible TLS certificate and private key

Example files are included for development and experimentation only.

## Build

From the repository root:

```bash
cargo build
```

## Run

The application takes three arguments:

```bash
cargo run -- <cfg_path> <der_path> <pkcs12_path>
```

Example server startup:

```bash
cargo run -- test_conf.json certificate.der identity.p12
```

Example client startup:

```bash
cargo run -- test_conf_client.json certificate.der identity.p12
```

## Configuration

Configuration is provided as JSON.

Example server config:

```json
{
  "mode": "server",
  "address": "127.0.0.1:8000",
  "blocked_addresses": ["127.0.0.2:8000"],
  "logfile_path": "minilink.log",
  "log": true,
  "domain": "localhost",
  "password": "your-password",
  "user_db_path": "users.db"
}
```

Example client config:

```json
{
  "mode": "client",
  "address": "127.0.0.1:8000",
  "blocked_addresses": ["127.0.0.2:8000"],
  "logfile_path": "minilink.log",
  "log": true,
  "domain": "localhost",
  "password": "your-password",
  "entry_message": "CLIENT_CONNECTED",
  "is_radio": false
}
```

## Messaging behavior

Client messages are relayed by the server to all other connected clients. The server also tracks client names assigned with:

```text
setname Alice
```

Those names are used for display and tracking.

## Logging

When enabled, operational activity is written to the configured logfile path. The server console can snapshot the current log with:

```text
save_log
```

## Status

This repository is an early prototype. The current focus is on:

- secure transport
- message propagation
- operator visibility
- identity tracking
- simple event logging
- simple user management via a database

Future enhancements may include richer message formats, permission models, lifecycle handling, protocol framing, and operational hardening.

## Notes

minilink is designed as a research and development sandbox for tactical datalink concepts, local testing, and protocol exploration.