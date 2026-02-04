package seal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// GetSealBaseDir returns the OS-appropriate base directory for Seal data.
func GetSealBaseDir() (string, error) {
	var baseDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
		}
		baseDir = filepath.Join(home, "Library", "Application Support", "seal")

	case "windows":
		appData := os.Getenv("AppData")
		if appData == "" {
			return "", errors.New("AppData environment variable not set")
		}
		baseDir = filepath.Join(appData, "seal")

	default: // Linux and other Unix-like systems
		xdgDataHome := os.Getenv("XDG_DATA_HOME")
		if xdgDataHome != "" {
			baseDir = filepath.Join(xdgDataHome, "seal")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("cannot get home directory: %w", err)
			}
			baseDir = filepath.Join(home, ".local", "share", "seal")
		}
	}

	return baseDir, nil
}

// loadMetadata loads and parses the metadata file for an item.
func loadMetadata(itemDir string) (SealedItem, error) {
	metaPath := filepath.Join(itemDir, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return SealedItem{}, fmt.Errorf("failed to read metadata: %w", err)
	}

	var item SealedItem
	if err := json.Unmarshal(metaData, &item); err != nil {
		return SealedItem{}, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return item, nil
}

// saveMetadata saves the metadata file for an item atomically.
func saveMetadata(itemDir string, item SealedItem) error {
	metaPath := filepath.Join(itemDir, "meta.json")
	metaJSON, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	tmpMetaPath := metaPath + ".tmp"
	if err := os.WriteFile(tmpMetaPath, metaJSON, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	if err := os.Rename(tmpMetaPath, metaPath); err != nil {
		os.Remove(tmpMetaPath)
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	return nil
}
