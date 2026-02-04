package seal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seal/internal/testutil"
)

// Test case A: state is unlocked but unsealed file is missing
func TestValidateItemState_UnlockedButUnsealedMissing(t *testing.T) {
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
	
	// Manually corrupt: change state to unlocked without creating unsealed file
	meta, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}
	
	corruptedMeta := strings.Replace(string(meta), `"state": "sealed"`, `"state": "unlocked"`, 1)
	if err := os.WriteFile(filepath.Join(itemDir, "meta.json"), []byte(corruptedMeta), 0600); err != nil {
		t.Fatalf("failed to write corrupted metadata: %v", err)
	}

	// Load and validate
	item, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read corrupted metadata: %v", err)
	}
	
	var sealedItem SealedItem
	if err := json.Unmarshal(item, &sealedItem); err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	// Validation should fail
	err = ValidateItemState(sealedItem, itemDir)
	if err == nil {
		t.Fatal("expected validation error for unlocked state with missing unsealed file")
	}

	if !strings.Contains(err.Error(), "unlocked but unsealed file missing") {
		t.Errorf("error should mention missing unsealed file, got: %v", err)
	}

	if !strings.Contains(err.Error(), id) {
		t.Errorf("error should mention item ID, got: %v", err)
	}
}

// Test case B: state is sealed but unsealed file exists
func TestValidateItemState_SealedButUnsealedExists(t *testing.T) {
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
	
	// Manually corrupt: create unsealed file while state is sealed
	unsealedPath := filepath.Join(itemDir, "unsealed")
	if err := os.WriteFile(unsealedPath, []byte("corrupt data"), 0600); err != nil {
		t.Fatalf("failed to create corrupt unsealed file: %v", err)
	}

	// Load and validate
	item, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}
	
	var sealedItem SealedItem
	if err := json.Unmarshal(item, &sealedItem); err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	// Validation should fail
	err = ValidateItemState(sealedItem, itemDir)
	if err == nil {
		t.Fatal("expected validation error for sealed state with unsealed file present")
	}

	if !strings.Contains(err.Error(), "sealed but unsealed file exists") {
		t.Errorf("error should mention unsealed file exists, got: %v", err)
	}

	if !strings.Contains(err.Error(), id) {
		t.Errorf("error should mention item ID, got: %v", err)
	}
}

// Test case C: valid sealed item passes validation
func TestValidateItemState_ValidSealed(t *testing.T) {
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
	
	// Load and validate
	item, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}
	
	var sealedItem SealedItem
	if err := json.Unmarshal(item, &sealedItem); err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	// Validation should pass
	err = ValidateItemState(sealedItem, itemDir)
	if err != nil {
		t.Errorf("validation should pass for valid sealed item, got: %v", err)
	}
}

// Test case D: valid unlocked item passes validation
func TestValidateItemState_ValidUnlocked(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create a sealed item with a past time
	// Use test genesis: 1677685200, period: 3 seconds
	// For a time 1 hour ago, the target round will be around:
	// (now - 3600 - genesis) / 3
	// With current time ~1738636800, that's (1738633200 - 1677685200) / 3 = ~20316000
	// So we need currentRound to be higher than that
	pastTime := time.Now().UTC().Add(-1 * time.Hour)
	authority := newTestDrandAuthority(999999999) // Very high round to ensure it's past target
	plaintext := []byte("test data")
	
	id, err := CreateSealedItem(pastTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("failed to create sealed item: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	itemDir := filepath.Join(baseDir, id)
	
	// Load item
	metaBytes, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}
	
	var sealedItem SealedItem
	if err := json.Unmarshal(metaBytes, &sealedItem); err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	// Use TryMaterialize with test authority to unlock the item
	unlockedItem, err := TryMaterialize(sealedItem, itemDir, authority)
	if err != nil {
		t.Fatalf("materialization failed: %v", err)
	}

	if unlockedItem.State != StateUnlocked {
		t.Fatalf("expected state unlocked, got %s", unlockedItem.State)
	}

	// Validation should pass for unlocked item with unsealed file
	err = ValidateItemState(unlockedItem, itemDir)
	if err != nil {
		t.Errorf("validation should pass for valid unlocked item, got: %v", err)
	}
}
