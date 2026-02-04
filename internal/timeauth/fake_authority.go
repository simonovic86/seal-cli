package timeauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// FakeAuthority is a deterministic time authority for testing.
// It allows control over round calculation, randomness injection, and failure simulation.
type FakeAuthority struct {
	// AuthorityName is the name returned by Name()
	AuthorityName string

	// RoundMapping maps unlock times to round numbers
	RoundMapping map[time.Time]uint64

	// DefaultRound is used if unlock time is not in RoundMapping
	DefaultRound uint64

	// RandomnessMap provides randomness for specific rounds
	RandomnessMap map[uint64][]byte

	// DefaultRandomness is used if round is not in RandomnessMap
	DefaultRandomness []byte

	// EncryptError simulates encryption failures
	EncryptError error

	// DecryptError simulates decryption failures
	DecryptError error

	// RoundAtError simulates round calculation failures
	RoundAtError error

	// CanUnlockError simulates availability check failures
	CanUnlockError error

	// CurrentRound is the current round for CanUnlock checks
	CurrentRound uint64
}

func (f *FakeAuthority) Name() string {
	if f.AuthorityName == "" {
		return "fake"
	}
	return f.AuthorityName
}

func (f *FakeAuthority) RoundAt(unlockTime time.Time) (uint64, error) {
	if f.RoundAtError != nil {
		return 0, f.RoundAtError
	}

	if f.RoundMapping != nil {
		if round, ok := f.RoundMapping[unlockTime]; ok {
			return round, nil
		}
	}

	return f.DefaultRound, nil
}

func (f *FakeAuthority) TimeLockEncrypt(data []byte, targetRound uint64) (string, error) {
	if f.EncryptError != nil {
		return "", f.EncryptError
	}

	// Simple fake: base64 encode with prefix
	return "FAKE_TLOCK:" + base64.StdEncoding.EncodeToString(data), nil
}

func (f *FakeAuthority) TimeLockDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error) {
	if f.DecryptError != nil {
		return nil, f.DecryptError
	}

	// Reverse the fake encoding
	if strings.HasPrefix(ciphertextB64, "FAKE_TLOCK:") {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertextB64, "FAKE_TLOCK:"))
	}

	return nil, fmt.Errorf("invalid fake tlock ciphertext")
}

func (f *FakeAuthority) CanUnlock(ctx context.Context, targetRound uint64) (bool, error) {
	if f.CanUnlockError != nil {
		return false, f.CanUnlockError
	}

	return f.CurrentRound >= targetRound, nil
}

// Lock creates a fake key reference (for backward compatibility).
func (f *FakeAuthority) Lock(unlockTime time.Time) (KeyReference, error) {
	round, err := f.RoundAt(unlockTime)
	if err != nil {
		return "", err
	}

	return KeyReference(fmt.Sprintf(`{"network":"fake","target_round":%d}`, round)), nil
}
