package seal

import (
	"fmt"
	"path/filepath"
)

// StatusResult contains the results of a status check.
type StatusResult struct {
	Items                  []SealedItem
	MaterializationFailed  bool
	FirstError             error
}

// GetStatus retrieves all sealed items and attempts materialization.
func GetStatus() (StatusResult, error) {
	items, err := ListSealedItems()
	if err != nil {
		return StatusResult{}, err
	}

	if len(items) == 0 {
		return StatusResult{Items: items}, nil
	}

	baseDir, err := GetSealBaseDir()
	if err != nil {
		return StatusResult{}, err
	}

	// Track materialization errors
	var materializationFailed bool
	var firstError error

	// Attempt materialization for each item, then report post-materialization state
	for i := range items {
		itemDir := filepath.Join(baseDir, items[i].ID)
		
		// Attempt materialization (idempotent - no-op if already unlocked)
		// CheckAndTransitionUnlock handles metadata persistence via saveMetadata
		updatedItem, err := CheckAndTransitionUnlock(items[i], itemDir)
		if err != nil {
			// Track error but continue processing other items
			if !materializationFailed {
				firstError = err
				materializationFailed = true
			}
			// Item remains in its current state (sealed)
		} else {
			// Update to post-materialization state
			items[i] = updatedItem
		}
	}

	return StatusResult{
		Items:                 items,
		MaterializationFailed: materializationFailed,
		FirstError:            firstError,
	}, nil
}

// FormatStatusOutput formats status items for display.
func FormatStatusOutput(items []SealedItem) string {
	if len(items) == 0 {
		return "no sealed items"
	}

	result := ""
	for _, item := range items {
		result += fmt.Sprintf("id: %s\nstate: %s\nunlock_time: %s\ninput_type: %s\n\n",
			item.ID,
			item.State,
			item.UnlockTime.Format("2006-01-02T15:04:05Z07:00"),
			item.InputType)
	}

	return result
}
