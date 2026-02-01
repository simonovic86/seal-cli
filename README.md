# seal

Irreversible time-locked commitment primitive.

## Build

```bash
go build -o seal
```

## Usage

```
seal - irreversible time-locked commitment primitive

Usage:
  seal lock <path> --until <time>
  seal lock --until <time>          (reads from stdin)
  seal status

Options:
  --until <time>    RFC3339 timestamp for unlock time

seal lock encrypts data until a specified future time.
seal status shows information about sealed commitments.

No undo. No early unlock. No recovery.
```

## Project Structure

```
seal-cli/
├── go.mod              # Go module definition
├── main.go             # CLI implementation
├── PROJECT_CONTEXT.md.md  # Design constraints
└── README.md           # This file
```

## Implementation Status

- [x] CLI argument parsing
- [x] Command dispatch (lock, status)
- [x] Strict validation (RFC3339 time format, future time check, file existence)
- [ ] Cryptographic implementation (not yet implemented)
- [ ] Time-locking mechanism (not yet implemented)
