# Seal

**Irreversible time-locked commitment primitive for the command line**

[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Seal encrypts data and delegates the decision of when it can be decrypted to a public time authority. Once sealed, you cannot manually unlock the data — only time can.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Limitations](#limitations)
- [Design Principles](#design-principles)
- [Architecture](#architecture)
- [License](#license)

---

## Overview

Seal is a **commitment primitive**: you are making an irreversible decision to remove your own ability to access data until a future point in time.

**Key Features:**
- 🔒 AES-256-GCM encryption with time-locked keys
- ⏰ Time authority via [drand](https://drand.love/) public randomness beacon
- 🚫 No manual unlock, no recovery flows, no "undo"
- 💾 Crash-safe with atomic state transitions
- 🔍 Built-in corruption detection

**Use Cases:**
- Digital commitment devices
- Self-imposed access restrictions
- Time-delayed information release
- Research on commitment mechanisms

---

## Quick Start

```bash
# Build the binary
go build -o seal ./cmd/seal

# Lock a secret until a specific time
echo "secret message" | ./seal lock --until 2026-12-31T23:59:59Z

# Check status of sealed items
./seal status
```

---

## Installation

### From Source

```bash
git clone https://github.com/simonovic86/seal-cli.git
cd seal-cli
go build -o seal ./cmd/seal
```

### Requirements

- Go 1.24 or higher
- Internet connection (for drand time authority)

---

## Usage

### Commands

#### `seal lock` - Encrypt and time-lock data

```bash
# Lock a file
seal lock secret.txt --until 2026-06-15T10:00:00Z

# Lock from stdin
echo "secret message" | seal lock --until 2026-06-15T10:00:00Z

# Lock with file shredding (best-effort)
seal lock secret.txt --until 2026-06-15T10:00:00Z --shred

# Lock with clipboard clearing (best-effort)
pbpaste | seal lock --until 2026-06-15T10:00:00Z --clear-clipboard
```

**Output:** Prints only the item ID (UUID) to stdout on success.

#### `seal status` - View sealed items

```bash
seal status
```

**Output:**
```
id: a1b2c3d4-5e6f-7890-abcd-ef1234567890
state: sealed
unlock_time: 2026-12-31T23:59:59Z
input_type: stdin

id: f1e2d3c4-b5a6-9807-1234-567890abcdef
state: unlocked
unlock_time: 2026-01-15T08:00:00Z
input_type: file
```

**Behavior:**
- Attempts passive materialization for eligible items
- Reports post-materialization state
- No special messages when items unlock
- Exits with code 1 if materialization or validation fails

---

## How It Works

### Time-Based Unlocking

1. **Seal creates a time-locked encryption:**
   - Generates a random 256-bit key (DEK)
   - Encrypts your data with AES-256-GCM
   - Time-locks the DEK using drand/tlock to a specific round
   - Stores encrypted data + time-locked DEK

2. **Unlocking requires drand:**
   - Calculates target drand round from unlock time
   - Fetches randomness from drand network for that round
   - Uses randomness to decrypt the DEK via tlock
   - Decrypts data with recovered DEK

3. **Materialization is passive:**
   - Happens only when you run `seal status`
   - Uses two-phase commit for crash-safety
   - Creates `unsealed` file in item directory
   - Updates metadata atomically

### File Layout

```
~/Library/Application Support/seal/  (macOS)
~/.local/share/seal/                 (Linux)
%AppData%/seal/                      (Windows)
  └── <item-id>/
      ├── meta.json       # Item metadata and state
      ├── payload.bin     # AES-256-GCM encrypted data
      └── unsealed        # Decrypted data (appears after unlock)
```

---

## Limitations

### What Seal Cannot Do

⚠️ **Seal is not a password manager** - It does not help you manage credentials or secrets for regular use.

⚠️ **Seal is not a backup system** - It does not protect against data loss or hardware failure.

⚠️ **Seal does not prevent pre-sealing copies** - Any backups, screenshots, or copies made before running `seal lock` remain accessible.

⚠️ **Seal cannot defeat filesystem snapshots** - Time Machine, ZFS snapshots, Btrfs, etc. may retain original data.

⚠️ **Seal cannot protect you from yourself before sealing** - Preparation (copying files, taking screenshots) happens outside Seal's control.

⚠️ **Seal depends on drand** - If drand becomes unavailable or stops producing randomness, your data cannot be unlocked.

### Best-Effort Operations

Some operations are explicitly **best-effort only** and come with mandatory warnings:

**File Shredding (`--shred`)**
- Overwrites file with zeros before deletion
- **Not guaranteed** on modern SSDs, CoW filesystems, or systems with snapshots
- Warning always printed and cannot be suppressed

**Clipboard Clearing (`--clear-clipboard`)**
- Attempts to clear system clipboard after sealing
- **Not guaranteed** - OS or other apps may have copied data
- Warning always printed and cannot be suppressed
- macOS only (other platforms warn about no support)

---

## Design Principles

Seal enforces irreversibility through architectural constraints:

- ✋ **No undo, cancel, extend, or early unlock** - Not features to add, but constraints that give Seal meaning
- 🔐 **No accounts, authentication, or recovery flows** - Simplicity reduces attack surface
- 💬 **No interactive prompts** - Decisions are final when command executes
- 📢 **Honest about limitations** - Explicit warnings for best-effort operations
- 👤 **User is adversarial after sealing** - Seal assumes you will try to circumvent it
- ⏱️ **External time authority** - Local clock cannot be trusted

**Mental Model:** Using Seal means accepting that you are no longer the authority over when data becomes accessible. Time is.

If you need access to your data at arbitrary times, Seal is not the right tool.

For detailed philosophy, see [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md).

---

## Architecture

### Package Structure

```
seal-cli/
├── cmd/seal/              # CLI entry point
├── internal/
│   ├── seal/             # Core sealing logic
│   │   ├── model.go      # Data structures and constants
│   │   ├── seal.go       # Lock workflow
│   │   ├── materialize.go # Unlock transitions
│   │   ├── storage.go    # Metadata persistence
│   │   ├── listing.go    # Read-only enumeration
│   │   ├── status.go     # Status orchestration
│   │   └── invariants.go # State validation
│   └── timeauth/         # Time authority abstraction
│       ├── timeauth.go   # Interfaces and drand impl
│       ├── drand_prod.go # Production configuration
│       └── drand_testmode.go # Test mode
└── internal/testutil/    # Shared test utilities
```

### State Machine

```
┌─────────┐                    ┌───────────┐
│ sealed  │ ─── unlock time ──>│ unlocked  │
│         │     + seal status   │           │
└─────────┘                    └───────────┘
     │                               │
     │ Invariant:                    │ Invariant:
     │ unsealed file                 │ unsealed file
     │ MUST NOT exist                │ MUST exist
     └───────────────────────────────┘
```

### Crash Safety

Materialization uses a two-phase commit protocol:

1. **Phase 1 (Prepare):** Write `unsealed.pending` to disk
2. **Phase 2 (Commit):** Update metadata to `state: unlocked`, then rename pending → unsealed

**Recovery:** On next run, if `unsealed.pending` exists:
- If `state=unlocked`: complete transaction (rename pending → unsealed)
- If `state=sealed`: abort transaction (remove pending)

This ensures atomicity regardless of when the process crashes.

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/seal
go test ./internal/timeauth
go test ./cmd/seal

# Run with coverage
go test ./... -cover
```

**Test Organization:**
- `internal/seal/*_test.go` - Domain logic tests (38 tests)
- `internal/timeauth/*_test.go` - Time authority tests (10 tests)
- `cmd/seal/*_test.go` - CLI integration tests (25 tests)
- Total: 73 tests with crash-safety coverage

---

## Contributing

This is a personal research project. Issues and pull requests are welcome for:
- Bug fixes
- Security improvements
- Test coverage enhancements

**Not Accepting:**
- Early unlock features
- Recovery mechanisms
- Convenience features that weaken commitment semantics

---

## Related Work

- [drand](https://drand.love/) - Public randomness beacon network
- [tlock](https://github.com/drand/tlock) - Time-lock encryption library
- Original Seal (web version) - Browser-based implementation

---

## License

MIT License - see [LICENSE](LICENSE) for details.

**Additional Notice:** This software intentionally removes your ability to access encrypted data until a specified future time. There is no recovery mechanism, no warranty, and no guarantee of data accessibility. External dependencies (drand) may become unavailable.

**Use at your own risk.** Make sure you understand the implications before using Seal.
