package seal

import (
	"fmt"
	"os"
	"path/filepath"
)

// State invariants:
//
// If state == StateSealed:
//     unsealed file MUST NOT exist
//     unsealed.pending MAY exist (will be cleaned up by recovery)
//
// If state == StateUnlocked:
//     unsealed file MUST exist (or unsealed.pending if recovery incomplete)
//
// These invariants apply to every sealed item directory.

// ValidateItemState verifies that an item's state is consistent with filesystem state.
// This function inspects the filesystem and returns an error if invariants are violated.
// It NEVER attempts automatic repair and NEVER mutates disk.
// Note: unsealed.pending files are handled by recovery logic, not validation.
func ValidateItemState(item SealedItem, itemDir string) error {
	unsealedPath := filepath.Join(itemDir, "unsealed")
	pendingPath := filepath.Join(itemDir, "unsealed.pending")
	
	_, unsealedErr := os.Stat(unsealedPath)
	unsealedExists := unsealedErr == nil
	
	_, pendingErr := os.Stat(pendingPath)
	pendingExists := pendingErr == nil

	switch item.State {
	case StateSealed:
		// Invariant: unsealed file must NOT exist
		// Note: pending files are allowed and will be cleaned up by recovery
		if unsealedExists {
			return fmt.Errorf("item %s: state is sealed but unsealed file exists (corrupted)", item.ID)
		}
		return nil

	case StateUnlocked:
		// Invariant: unsealed file must exist (or pending if recovery incomplete)
		if !unsealedExists && !pendingExists {
			if os.IsNotExist(unsealedErr) {
				return fmt.Errorf("item %s: state is unlocked but unsealed file missing (corrupted)", item.ID)
			}
			return fmt.Errorf("item %s: state is unlocked but cannot verify unsealed file: %w", item.ID, unsealedErr)
		}
		return nil

	default:
		return fmt.Errorf("item %s: unknown state %q", item.ID, item.State)
	}
}
