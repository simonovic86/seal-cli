# timeauth Package

The `timeauth` package provides the **Authority abstraction** - a strict boundary between Seal's core logic and external time providers.

## Philosophy

Seal is a commitment primitive that delegates unlock timing to an external, verifiable time authority. The Authority abstraction ensures:

- **Single responsibility**: Time authorities only manage temporal unlock logic
- **Implementation independence**: Seal logic never depends on provider specifics
- **Testability**: Fake authorities enable deterministic, offline testing
- **Future extensibility**: New time providers can be added without changing Seal's core

## Authority Interface

The `Authority` interface defines the complete contract between Seal and time providers:

```go
type Authority interface {
    Name() string
    RoundAt(unlockTime time.Time) (uint64, error)
    Lock(unlockTime time.Time) (KeyReference, error)
    TimeLockEncrypt(data []byte, targetRound uint64) (string, error)
    TimeLockDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error)
    CanUnlock(ctx context.Context, targetRound uint64) (bool, error)
}
```

### Method Responsibilities

#### `Name() string`
- Returns a unique identifier for the authority
- Used in metadata to record which authority locked the data
- Must be deterministic and never change for a given implementation

#### `RoundAt(unlockTime time.Time) (uint64, error)`
- Calculates the round number corresponding to an unlock time
- Round numbers must be monotonically increasing
- Must return error if unlock time is before authority's genesis
- Used during sealing to determine target round

#### `Lock(unlockTime time.Time) (KeyReference, error)`
- Creates an opaque key reference for metadata storage
- Preserves authority-specific format (e.g., drand's JSON with network + round)
- Used for backward compatibility and metadata verification

#### `TimeLockEncrypt(data []byte, targetRound uint64) (string, error)`
- Encrypts data using time-lock encryption to a specific round
- Data becomes decryptable only after the round's randomness is published
- Returns base64-encoded ciphertext
- Must return empty string (no error) if authority doesn't support time-locking

#### `TimeLockDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error)`
- Decrypts time-locked ciphertext
- Fetches randomness for the target round internally
- Returns error if round not yet reached or network fails
- Context allows cancellation and timeout control

#### `CanUnlock(ctx context.Context, targetRound uint64) (bool, error)`
- Checks if the specified round has been reached
- Returns true if randomness is available, false otherwise
- Must not perform decryption - only availability check
- Used to avoid unnecessary decryption attempts

## Implementations

### Drand Authority (Production)

Located in `drand.go`, `drand_prod.go`, `drand_testmode.go`.

**Characteristics:**
- Uses [drand quicknet](https://drand.love/) public randomness beacon
- Rounds published every 3 seconds
- Genesis: 2023-03-01 13:00:00 UTC
- Network calls to `api.drand.sh`
- Uses [tlock](https://github.com/drand/tlock) for time-lock encryption

**Factory:**
```go
authority := timeauth.NewDefaultAuthority() // Returns drand in production
```

### Placeholder Authority

Located in `timeauth.go`.

**Characteristics:**
- No-op authority for testing
- Never permits unlocking
- Does not support time-lock encryption
- No network calls
- Used for testing seal logic without time dependencies

**Usage:**
```go
authority := &timeauth.PlaceholderAuthority{}
```

### Fake Authority (Testing)

Located in `fake_authority.go`.

**Characteristics:**
- Fully controllable for deterministic testing
- Configurable round mappings
- Simulated randomness injection
- Failure simulation (encrypt, decrypt, network errors)
- Thread-safe for parallel tests

**Usage:**
```go
fake := &timeauth.FakeAuthority{
    AuthorityName:     "test",
    DefaultRound:      1000,
    CurrentRound:      2000,
    DefaultRandomness: []byte("test-random"),
}
```

## Design Invariants

### Authority implementations MUST guarantee:

1. **Determinism**: Same unlock time always produces same round number
2. **Monotonicity**: Rounds are strictly increasing over time
3. **Finality**: Once a round's randomness is published, it never changes
4. **Verifiability**: Randomness can be independently verified
5. **No local clock trust**: Round determination must not rely on local system time

### Authority implementations MUST NOT:

1. Store state in Seal's data directories
2. Modify seal metadata format
3. Perform unlock decisions (only provide information)
4. Cache results across process boundaries without invalidation
5. Block indefinitely (respect context cancellation)

## Adding New Authorities

To add a new time authority:

1. **Implement the Authority interface** completely
2. **Add factory support** in `factory.go`
3. **Add contract tests** in `timeauth_contract_test.go`
4. **Document limitations** honestly (availability, latency, trust model)
5. **Provide build-tag or runtime configuration** for selection

### Example: Adding a hypothetical VDF authority

```go
// vdf.go
type VDFAuthority struct {
    // VDF-specific fields
}

func (v *VDFAuthority) Name() string { return "vdf" }
func (v *VDFAuthority) RoundAt(t time.Time) (uint64, error) { /* VDF logic */ }
// ... implement remaining methods

// factory.go
func NewVDFAuthority() Authority {
    return &VDFAuthority{ /* config */ }
}
```

## Testing Guidelines

### Unit Tests
- Test each Authority method independently
- Use fake HTTP clients (no real network calls)
- Verify error propagation
- Test edge cases (genesis time, far future, network failures)

### Contract Tests
- Verify all authorities satisfy identical interface expectations
- Test that Drand, Placeholder, and Fake behave consistently
- Ensure determinism and offline compatibility

### Integration Tests
- Use Fake authority for seal package tests
- Use testmode drand for CLI tests
- Never depend on real drand network in tests

## Package Boundaries

### What timeauth exports:
- `Authority` interface
- `NewDefaultAuthority()` factory
- Public authority types (`PlaceholderAuthority`, `FakeAuthority`)
- Test helpers in build-tagged files

### What timeauth hides:
- Drand HTTP client implementation
- Round calculation algorithms
- Network protocol details
- Caching strategies

### What seal must never import:
- `DrandAuthority` type (use `Authority` interface)
- `DrandKeyReference` struct
- Any drand-specific constants or helpers
- Provider-specific network types

## Crash Safety

Authorities must be designed with crash safety in mind:

- **Idempotent operations**: Calling methods multiple times is safe
- **No partial state**: Either operation succeeds fully or fails cleanly
- **Network resilience**: Handle timeouts, retries, and failures gracefully
- **Resource cleanup**: Don't leak connections, goroutines, or file handles

## Security Considerations

- **Randomness quality**: Authority must provide cryptographically secure randomness
- **Verification**: Randomness must be independently verifiable
- **No backdoors**: Authority must not allow early unlock under any circumstances
- **Honest limitations**: Document attack vectors and trust assumptions clearly

---

For implementation philosophy, see [`PROJECT_CONTEXT.md`](../../PROJECT_CONTEXT.md) in the repository root.
