# seal

Time-locked data commitment tool.

## What Seal is

Seal encrypts data and delegates the decision of when it can be decrypted to a public time authority. Once sealed, you cannot manually unlock the data — only time can.

The tool encrypts your data using AES-256-GCM and time-locks the decryption key using drand (a public randomness beacon). When the specified unlock time is reached and Seal code is executed, the data can materialize.

Seal is a commitment primitive: you are making an irreversible decision to remove your own ability to access data until a future point in time.

## What Seal is not

- Seal is **not a password manager**. It does not help you manage credentials or secrets for regular use.
- Seal is **not a backup system**. It does not protect against data loss or hardware failure.
- Seal **does not prevent copies made before sealing**. Any backups, screenshots, or copies you made before running `seal lock` remain accessible.
- Seal **does not defeat filesystem snapshots, backups, or malware**. If your system creates automatic snapshots (Time Machine, ZFS, Btrfs, etc.), the original data may still exist in those snapshots.
- Seal **cannot protect you from yourself before sealing**. Any preparation you do (copying files, taking screenshots, etc.) is outside Seal's control.

## How unlocking works

There is no `seal unlock` command.

Unlocking is a state transition that happens automatically when two conditions are met:

1. The time authority (drand) confirms that the specified unlock time has been reached
2. Seal code is executed (e.g., by running `seal status`)

Think of it like a photograph: the state doesn't change until you observe it. A sealed item remains in the "sealed" state until you run `seal status`, at which point Seal checks with the time authority and materializes the data if the unlock time has passed.

Running `seal status` is idempotent. If an item is already unlocked, running status again does nothing.

## Time authority (drand)

Seal uses [drand](https://drand.love/) (quicknet) as its default time authority. Drand is a public randomness beacon that produces verifiable random values at regular intervals (every 3 seconds).

When you seal data, Seal:
- Calculates which drand round corresponds to your specified unlock time
- Uses drand/tlock to time-lock the encryption key to that round
- Stores the encrypted data and the time-locked key

When the unlock time is reached:
- Seal fetches the drand randomness for the target round
- tlock uses that randomness to decrypt the encryption key
- Seal uses the key to decrypt your data

Seal does not trust your local system clock. The unlock time is determined by drand's public randomness beacon, which cannot be manipulated by you or anyone else.

Drand is not magic. It is a distributed network of servers. If drand becomes unavailable or stops producing randomness, Seal cannot unlock your data. This is a fundamental limitation of depending on an external time authority.

## Best-effort operations

Some operations in Seal are explicitly best-effort:

- `--shred` attempts to overwrite file contents before deletion, but modern filesystems (SSDs, copy-on-write filesystems, snapshots) may retain the original data. Seal prints a mandatory warning when you use this flag.
- `--clear-clipboard` attempts to clear the system clipboard after sealing, but the OS or other applications may have already copied the data. Seal prints a mandatory warning when you use this flag.

These warnings cannot be suppressed. They exist to remind you that these operations are not guarantees.

## Build

```bash
go build -o seal
```

## Usage

```
seal - time-locked data commitment primitive

Usage:
  seal lock <path> --until <time> [--shred]
  seal lock --until <time> [--clear-clipboard]  (reads from stdin)
  seal status

Options:
  --until <time>         RFC3339 timestamp for unlock time (e.g. 2025-12-31T23:59:59Z)
  --shred                best-effort file shredding (file input only)
  --clear-clipboard      best-effort clipboard clearing (stdin only)

Examples:
  seal lock secret.txt --until 2025-06-15T10:00:00Z
  echo "secret" | seal lock --until 2025-06-15T10:00:00Z
  seal status
```

### seal lock

Encrypts data and stores it until the specified time.

- Reads from a file or stdin
- Requires a future timestamp in RFC3339 format
- Outputs only the item ID on success
- No undo, no cancel, no early unlock

### seal status

Lists all sealed items and their current state.

- Attempts materialization for items whose unlock time has passed
- Reports the post-materialization state (sealed or unlocked)
- Prints no special messages when items transition from sealed to unlocked
- Exits with non-zero status if materialization fails

## Mental model

Using Seal means accepting that you are no longer the authority over when data becomes accessible again. Time is.

You cannot change your mind. You cannot unlock early. You cannot extend the time. These are not features to be added later — they are the core constraint that makes Seal meaningful.

If you need access to your data at arbitrary times, Seal is not the right tool.

## Design principles

- No undo, cancel, extend, or early unlock
- No accounts, no authentication, no recovery flows
- No interactive prompts or "are you sure?" dialogs
- Honest about limitations (SSD shredding, clipboard clearing, backups)
- The user is considered adversarial after sealing
- Time-based locking relies on an external, verifiable time authority (drand)

For more details, see `PROJECT_CONTEXT.md`.

## License

This is a personal project. No license or warranty provided.
