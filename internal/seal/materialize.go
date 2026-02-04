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

// recoverPendingUnseal handles incomplete unseal transactions.
// If unsealed.pending exists:
//   - If state=unlocked: complete the transaction (rename pending → unsealed)
//   - If state=sealed: abort the transaction (remove pending)
func recoverPendingUnseal(item SealedItem, itemDir string) error {
	pendingPath := filepath.Join(itemDir, "unsealed.pending")
	unsealedPath := filepath.Join(itemDir, "unsealed")

	// Check if pending file exists
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		// No pending transaction
		return nil
	}

	switch item.State {
	case StateUnlocked:
		// Transaction was committed but rename didn't complete
		// Complete the commit by renaming pending → unsealed
		if err := os.Rename(pendingPath, unsealedPath); err != nil {
			// If unsealed already exists, remove pending (already recovered)
			if _, statErr := os.Stat(unsealedPath); statErr == nil {
				os.Remove(pendingPath)
				return nil
			}
			return fmt.Errorf("failed to recover pending unseal: %w", err)
		}
		return nil

	case StateSealed:
		// Transaction was not committed (crash before metadata update)
		// Abort by removing pending file
		os.Remove(pendingPath)
		return nil

	default:
		// Unknown state - leave pending file for manual inspection
		return nil
	}
}

// TryMaterialize attempts to materialize (unlock) a sealed item.
// Materialization is passive - it only occurs when Seal code executes (e.g., seal status).
// Returns the item (potentially with updated state) and any error.
//
// Decrypted data is written to: <itemDir>/unsealed
// This path must not exist while the item is in StateSealed state.
func TryMaterialize(item SealedItem, itemDir string, authority timeauth.TimeAuthority) (SealedItem, error) {
	// Recover any incomplete transactions first
	if err := recoverPendingUnseal(item, itemDir); err != nil {
		return item, fmt.Errorf("failed to recover pending transaction: %w", err)
	}

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

	// Two-phase commit protocol for crash-safety:
	// Phase 1: Write unsealed data with .pending suffix (not yet committed)
	// Phase 2: Update metadata to unlocked, then rename .pending to final name
	//
	// This ensures atomicity:
	// - If crash before metadata update: .pending exists but state=sealed (will be cleaned up)
	// - If crash after metadata update: .pending exists and state=unlocked (will be recovered)
	// - If crash after rename: unsealed exists and state=unlocked (fully committed)

	unsealedPath := filepath.Join(itemDir, "unsealed")
	pendingPath := unsealedPath + ".pending"

	// Phase 1: Write unsealed data to pending location
	if err := os.WriteFile(pendingPath, plaintext, 0600); err != nil {
		return item, fmt.Errorf("failed to write unsealed data: %w", err)
	}

	// Sync pending file to disk
	pendingFile, err := os.OpenFile(pendingPath, os.O_RDONLY, 0)
	if err != nil {
		os.Remove(pendingPath)
		return item, fmt.Errorf("failed to open unsealed data for sync: %w", err)
	}
	if err := pendingFile.Sync(); err != nil {
		pendingFile.Close()
		os.Remove(pendingPath)
		return item, fmt.Errorf("failed to sync unsealed data: %w", err)
	}
	pendingFile.Close()

	// Phase 2: Commit transaction
	// First, update metadata to unlocked (this is the commit point)
	item.State = StateUnlocked
	if err := saveMetadata(itemDir, item); err != nil {
		// If metadata update fails, remove pending file and stay sealed
		os.Remove(pendingPath)
		item.State = StateSealed
		return item, err
	}

	// Then, atomically rename pending to final location
	if err := os.Rename(pendingPath, unsealedPath); err != nil {
		// Metadata says unlocked but rename failed
		// This will be recovered on next run by recoverPendingUnseal
		return item, fmt.Errorf("failed to finalize unsealed data: %w", err)
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
