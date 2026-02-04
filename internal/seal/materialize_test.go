package seal

import (
	"bytes"
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

// TestRecoverPendingUnseal_AbortSealed tests that pending files are removed if state is sealed
func TestRecoverPendingUnseal_AbortSealed(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create a sealed item
	authority := newTestDrandAuthority(1000)
	futureTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	
	id, err := CreateSealedItem(futureTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("failed to create sealed item: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	itemDir := filepath.Join(baseDir, id)
	pendingPath := filepath.Join(itemDir, "unsealed.pending")

	// Simulate crash: create pending file while state is still sealed
	if err := os.WriteFile(pendingPath, []byte("pending data"), 0600); err != nil {
		t.Fatalf("failed to create pending file: %v", err)
	}

	// Verify pending exists
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Fatal("pending file should exist before recovery")
	}

	// Load item and run recovery
	item, err := loadMetadata(itemDir)
	if err != nil {
		t.Fatalf("loadMetadata failed: %v", err)
	}

	// Attempt materialization (which calls recovery first)
	_, err = CheckAndTransitionUnlock(item, itemDir)
	if err != nil {
		t.Fatalf("checkAndTransitionUnlock failed: %v", err)
	}

	// Pending file should be removed (transaction aborted)
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("pending file should be removed for sealed state")
	}

	// Item should still be sealed
	updatedItem, _ := loadMetadata(itemDir)
	if updatedItem.State != StateSealed {
		t.Errorf("state should still be sealed, got %s", updatedItem.State)
	}
}

// TestRecoverPendingUnseal_CommitUnlocked tests that pending files are finalized if state is unlocked
func TestRecoverPendingUnseal_CommitUnlocked(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create a sealed item
	authority := newTestDrandAuthority(999999999) // Very high round
	pastTime := time.Now().UTC().Add(-1 * time.Hour)
	plaintext := []byte("test data to unlock")
	
	id, err := CreateSealedItem(pastTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("failed to create sealed item: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	itemDir := filepath.Join(baseDir, id)
	pendingPath := filepath.Join(itemDir, "unsealed.pending")
	unsealedPath := filepath.Join(itemDir, "unsealed")

	// Load item
	item, err := loadMetadata(itemDir)
	if err != nil {
		t.Fatalf("loadMetadata failed: %v", err)
	}

	// Materialize the item fully
	unlockedItem, err := TryMaterialize(item, itemDir, authority)
	if err != nil {
		t.Fatalf("TryMaterialize failed: %v", err)
	}

	if unlockedItem.State != StateUnlocked {
		t.Fatalf("expected unlocked state, got %s", unlockedItem.State)
	}

	// Verify unsealed exists
	if _, err := os.Stat(unsealedPath); os.IsNotExist(err) {
		t.Fatal("unsealed file should exist after materialization")
	}

	// Simulate incomplete recovery: manually replace unsealed with pending
	if err := os.Rename(unsealedPath, pendingPath); err != nil {
		t.Fatalf("failed to simulate pending state: %v", err)
	}

	// Verify pending exists and unsealed doesn't
	if _, err := os.Stat(pendingPath); os.IsNotExist(err) {
		t.Fatal("pending file should exist")
	}
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Fatal("unsealed file should not exist yet")
	}

	// Run recovery by calling TryMaterialize again (it's idempotent and runs recovery)
	recoveredItem, err := TryMaterialize(unlockedItem, itemDir, authority)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	if recoveredItem.State != StateUnlocked {
		t.Errorf("state should remain unlocked, got %s", recoveredItem.State)
	}

	// Pending should be renamed to unsealed
	if _, err := os.Stat(unsealedPath); os.IsNotExist(err) {
		t.Error("unsealed file should exist after recovery")
	}

	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("pending file should not exist after recovery")
	}
}

// TestMaterialize_AtomicCommit tests that materialization is atomic
func TestMaterialize_AtomicCommit(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create a sealed item eligible for unlock
	authority := newTestDrandAuthority(999999999)
	pastTime := time.Now().UTC().Add(-1 * time.Hour)
	plaintext := []byte("test atomic commit")
	
	id, err := CreateSealedItem(pastTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("failed to create sealed item: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	itemDir := filepath.Join(baseDir, id)
	unsealedPath := filepath.Join(itemDir, "unsealed")
	pendingPath := filepath.Join(itemDir, "unsealed.pending")

	// Load and materialize
	item, err := loadMetadata(itemDir)
	if err != nil {
		t.Fatalf("loadMetadata failed: %v", err)
	}

	unlockedItem, err := TryMaterialize(item, itemDir, authority)
	if err != nil {
		t.Fatalf("TryMaterialize failed: %v", err)
	}

	// Verify full transaction completed
	if unlockedItem.State != StateUnlocked {
		t.Errorf("expected unlocked state, got %s", unlockedItem.State)
	}

	// Verify unsealed file exists
	if _, err := os.Stat(unsealedPath); os.IsNotExist(err) {
		t.Error("unsealed file should exist")
	}

	// Verify no pending file remains
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Error("pending file should not exist after successful materialization")
	}

	// Verify metadata shows unlocked
	meta, err := loadMetadata(itemDir)
	if err != nil {
		t.Fatalf("loadMetadata failed: %v", err)
	}

	if meta.State != StateUnlocked {
		t.Errorf("metadata state should be unlocked, got %s", meta.State)
	}

	// Verify unsealed content matches plaintext
	unsealedData, err := os.ReadFile(unsealedPath)
	if err != nil {
		t.Fatalf("failed to read unsealed data: %v", err)
	}

	if !bytes.Equal(unsealedData, plaintext) {
		t.Error("unsealed data should match original plaintext")
	}
}
