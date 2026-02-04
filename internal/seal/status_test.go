package seal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"seal/internal/testutil"
	"seal/internal/timeauth"
)

func TestCheckAndTransitionUnlock_Inert(t *testing.T) {
	tmpDir := t.TempDir()
	itemDir := filepath.Join(tmpDir, "test-item")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	createdAt := time.Now().UTC()

	// Test with sealed item
	sealedItem := SealedItem{
		ID:            "test-id",
		State:         "sealed",
		UnlockTime:    unlockTime,
		InputType:     "stdin",
		TimeAuthority: "placeholder",
		CreatedAt:     createdAt,
		Algorithm:     "aes-256-gcm",
		Nonce:         "test-nonce",
		KeyRef:        "test-ref",
	}

	result, err := CheckAndTransitionUnlock(sealedItem, itemDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should remain sealed (inert implementation)
	if result.State != "sealed" {
		t.Errorf("state should remain sealed, got %s", result.State)
	}

	// Test with already unlocked item
	unlockedItem := SealedItem{
		ID:            "test-id-2",
		State:         "unlocked",
		UnlockTime:    unlockTime,
		InputType:     "stdin",
		TimeAuthority: "placeholder",
		CreatedAt:     createdAt,
		Algorithm:     "aes-256-gcm",
		Nonce:         "test-nonce",
		KeyRef:        "test-ref",
	}

	result, err = CheckAndTransitionUnlock(unlockedItem, itemDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should remain unlocked
	if result.State != "unlocked" {
		t.Errorf("state should remain unlocked, got %s", result.State)
	}
}

func TestPlaceholderSealedItems_NeverMaterialize(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create sealed item with placeholder authority and past unlock time
	pastTime := time.Now().UTC().Add(-24 * time.Hour)
	plaintext := []byte("test data")
	authority := &timeauth.PlaceholderAuthority{}

	id, err := CreateSealedItem(pastTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	itemDir := filepath.Join(baseDir, id)
	unsealedPath := filepath.Join(itemDir, "unsealed")

	// Run checkAndTransitionUnlock
	item, err := loadMetadata(itemDir)
	if err != nil {
		t.Fatalf("loadMetadata failed: %v", err)
	}

	result, err := CheckAndTransitionUnlock(item, itemDir)
	if err != nil {
		t.Fatalf("checkAndTransitionUnlock failed: %v", err)
	}

	// Should remain sealed (placeholder never unlocks)
	if result.State != "sealed" {
		t.Errorf("state should remain sealed for placeholder authority, got %s", result.State)
	}

	// Unsealed file should not exist
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist for placeholder authority")
	}

	// Verify metadata still shows sealed
	metaData, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	if meta.State != "sealed" {
		t.Errorf("metadata state should be sealed, got %s", meta.State)
	}
}
