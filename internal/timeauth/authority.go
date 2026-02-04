package timeauth

import (
	"context"
	"time"
)

// Authority is an external, verifiable source of truth for time-based unlocking.
// Implementations must provide deterministic round calculation, verifiable randomness,
// and time-lock encryption/decryption capabilities.
//
// The Authority abstraction separates sealing logic from time provider implementation.
// Seal depends only on this interface, never on provider-specific types or methods.
type Authority interface {
	// Name returns the identifier for this time authority.
	// Used in metadata to identify which authority was used for sealing.
	Name() string

	// RoundAt calculates the round number corresponding to a given unlock time.
	// Round numbers are monotonically increasing and correspond to discrete time intervals.
	// Returns an error if the unlock time is invalid for this authority.
	RoundAt(unlockTime time.Time) (uint64, error)

	// Lock creates an opaque key reference for the given unlock time.
	// Used to preserve authority-specific metadata format for backward compatibility.
	// Returns a KeyReference that can be stored in metadata.
	Lock(unlockTime time.Time) (KeyReference, error)

	// TimeLockEncrypt encrypts data using time-lock encryption to a specific round.
	// The data will only be decryptable once the randomness for that round is published.
	// Returns base64-encoded ciphertext.
	TimeLockEncrypt(data []byte, targetRound uint64) (string, error)

	// TimeLockDecrypt decrypts time-locked data.
	// Fetches the randomness for the target round and uses it to decrypt.
	// Returns an error if the round is not yet available or decryption fails.
	TimeLockDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error)

	// CanUnlock checks whether the specified round has been reached.
	// Returns true if randomness for the round is available, false otherwise.
	CanUnlock(ctx context.Context, targetRound uint64) (bool, error)
}

// KeyReference is an opaque reference to authority-specific unlock information.
// For round-based authorities, this typically encodes the target round number.
type KeyReference string
