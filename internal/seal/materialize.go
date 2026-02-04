package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"seal/internal/timeauth"
)

// TryMaterialize attempts to materialize (unlock) a sealed item.
// Materialization is passive - it only occurs when Seal code executes (e.g., seal status).
// Returns the item (potentially with updated state) and any error.
//
// Decrypted data is written to: <itemDir>/unsealed
// This path must not exist while the item is in StateSealed state.
func TryMaterialize(item SealedItem, itemDir string, authority timeauth.TimeAuthority) (SealedItem, error) {
	// Precondition: If already unlocked, no-op
	if item.State == StateUnlocked {
		return item, nil
	}

	// Precondition: Only materialize drand authority items
	if item.TimeAuthority != "drand" {
		return item, nil
	}

	// Precondition: Check if unlocking is allowed
	canUnlock, err := authority.CanUnlock(timeauth.KeyReference(item.KeyRef), time.Now())
	if err != nil {
		// Network failure - do not unlock
		return item, nil
	}

	if !canUnlock {
		// Not yet time to unlock
		return item, nil
	}

	// Verify tlock-encrypted DEK exists
	if item.DEKTlockB64 == "" {
		return item, errors.New("tlock-encrypted DEK not found")
	}

	// Get the DrandAuthority to access its Timelock
	drandAuth, ok := authority.(*timeauth.DrandAuthority)
	if !ok {
		return item, errors.New("expected DrandAuthority for drand items")
	}

	// Decrypt DEK using tlock (fetches drand beacon for target round)
	dek, err := drandAuth.Timelock.Decrypt(item.DEKTlockB64)
	if err != nil {
		// Decryption failure (too early or network error) - do not unlock
		return item, nil
	}
	defer func() {
		// Zero out DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Read encrypted payload
	payloadPath := filepath.Join(itemDir, "payload.bin")
	ciphertext, err := os.ReadFile(payloadPath)
	if err != nil {
		return item, fmt.Errorf("failed to read payload: %w", err)
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(item.Nonce)
	if err != nil {
		return item, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt payload
	block, err := aes.NewCipher(dek)
	if err != nil {
		return item, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return item, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return item, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	// Write unsealed data atomically
	unsealedPath := filepath.Join(itemDir, "unsealed")
	tmpUnsealedPath := unsealedPath + ".tmp"

	if err := os.WriteFile(tmpUnsealedPath, plaintext, 0600); err != nil {
		return item, fmt.Errorf("failed to write unsealed data: %w", err)
	}

	// Sync to disk
	tmpFile, err := os.OpenFile(tmpUnsealedPath, os.O_RDONLY, 0)
	if err != nil {
		os.Remove(tmpUnsealedPath)
		return item, fmt.Errorf("failed to open unsealed data for sync: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpUnsealedPath)
		return item, fmt.Errorf("failed to sync unsealed data: %w", err)
	}
	tmpFile.Close()

	// Atomic rename
	if err := os.Rename(tmpUnsealedPath, unsealedPath); err != nil {
		os.Remove(tmpUnsealedPath)
		return item, fmt.Errorf("failed to rename unsealed data: %w", err)
	}

	// Update state to unlocked
	item.State = StateUnlocked

	// Persist updated state
	if err := saveMetadata(itemDir, item); err != nil {
		return item, err
	}

	// Validate post-materialization invariants
	// This should never fail - if it does, it's a fatal internal error
	if err := ValidateItemState(item, itemDir); err != nil {
		return item, fmt.Errorf("internal error: post-materialization validation failed: %w", err)
	}

	return item, nil
}

// CheckAndTransitionUnlock wraps tryMaterialize with the appropriate authority.
func CheckAndTransitionUnlock(item SealedItem, itemDir string) (SealedItem, error) {
	if item.State == StateUnlocked {
		return item, nil
	}

	// Get authority based on item metadata
	var authority timeauth.TimeAuthority
	if item.TimeAuthority == "drand" {
		authority = timeauth.NewDefaultDrandAuthority()
	} else {
		// Placeholder or unknown authority - no materialization
		return item, nil
	}

	return TryMaterialize(item, itemDir, authority)
}
