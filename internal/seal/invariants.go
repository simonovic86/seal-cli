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
//
// If state == StateUnlocked:
//     unsealed file MUST exist
//
// These invariants apply to every sealed item directory.

// ValidateItemState verifies that an item's state is consistent with filesystem state.
// This function inspects the filesystem and returns an error if invariants are violated.
// It NEVER attempts automatic repair and NEVER mutates disk.
func ValidateItemState(item SealedItem, itemDir string) error {
	unsealedPath := filepath.Join(itemDir, "unsealed")
	_, err := os.Stat(unsealedPath)
	unsealedExists := err == nil

	switch item.State {
	case StateSealed:
		// Invariant: unsealed file must NOT exist
		if unsealedExists {
			return fmt.Errorf("item %s: state is sealed but unsealed file exists (corrupted)", item.ID)
		}
		return nil

	case StateUnlocked:
		// Invariant: unsealed file must exist
		if !unsealedExists {
			if os.IsNotExist(err) {
				return fmt.Errorf("item %s: state is unlocked but unsealed file missing (corrupted)", item.ID)
			}
			return fmt.Errorf("item %s: state is unlocked but cannot verify unsealed file: %w", item.ID, err)
		}
		return nil

	default:
		return fmt.Errorf("item %s: unknown state %q", item.ID, item.State)
	}
}
