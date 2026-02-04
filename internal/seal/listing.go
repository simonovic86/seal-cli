package seal

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ListSealedItems returns all sealed items, sorted by creation time (oldest first).
func ListSealedItems() ([]SealedItem, error) {
	baseDir, err := GetSealBaseDir()
	if err != nil {
		return nil, err
	}

	// Check if base directory exists
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		return []SealedItem{}, nil // No items yet
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read seal directory: %w", err)
	}

	var items []SealedItem
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		itemDir := filepath.Join(baseDir, entry.Name())
		item, err := loadMetadata(itemDir)
		if err != nil {
			// Skip invalid items
			continue
		}

		// Check and potentially transition unlock state (currently inert)
		item, err = CheckAndTransitionUnlock(item, itemDir)
		if err != nil {
			// Skip items that fail unlock check
			continue
		}

		items = append(items, item)
	}

	// Sort by creation time (oldest first)
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})

	return items, nil
}
