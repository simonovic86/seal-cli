package seal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"seal/internal/testutil"
	"seal/internal/timeauth"
)

func TestMaterialize_PlaceholderAuthority_NoOp(t *testing.T) {
	tmpDir := t.TempDir()
	itemDir := filepath.Join(tmpDir, "test-item")
	os.MkdirAll(itemDir, 0700)

	item := SealedItem{
		ID:            "test-id",
		State:         "sealed",
		UnlockTime:    time.Now().UTC().Add(-24 * time.Hour), // In the past
		TimeAuthority: "placeholder",
	}

	authority := &timeauth.PlaceholderAuthority{}

	result, err := TryMaterialize(item, itemDir, authority)
	if err != nil {
		t.Fatalf("tryMaterialize should not error for placeholder: %v", err)
	}

	// Should remain sealed (no-op for placeholder)
	if result.State != "sealed" {
		t.Errorf("state should remain sealed for placeholder authority, got %s", result.State)
	}

	// Unsealed file should not exist
	unsealedPath := filepath.Join(itemDir, "unsealed")
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist for placeholder authority")
	}
}

func TestMaterialize_AlreadyUnlocked_NoOp(t *testing.T) {
	tmpDir := t.TempDir()
	itemDir := filepath.Join(tmpDir, "test-item")

	item := SealedItem{
		ID:            "test-id",
		State:         "unlocked",
		TimeAuthority: "drand",
	}

	authority := newTestDrandAuthority(1000)

	result, err := TryMaterialize(item, itemDir, authority)
	if err != nil {
		t.Fatalf("tryMaterialize should not error for unlocked item: %v", err)
	}

	// Should remain unlocked
	if result.State != "unlocked" {
		t.Errorf("state should remain unlocked, got %s", result.State)
	}
}

func TestUnsealedPath_NeverCreated(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &timeauth.PlaceholderAuthority{}

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Verify unsealed path does not exist
	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	unsealedPath := filepath.Join(baseDir, id, "unsealed")

	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist for sealed item")
	}

	// List items (which calls checkAndTransitionUnlock)
	items, err := ListSealedItems()
	if err != nil {
		t.Fatalf("listSealedItems failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	// State should still be sealed
	if items[0].State != "sealed" {
		t.Errorf("state should be sealed, got %s", items[0].State)
	}

	// Unsealed path should still not exist after status check
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist after status check")
	}
}
