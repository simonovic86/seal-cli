package seal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seal/internal/testutil"
)

func TestListSealedItems_Empty(t *testing.T) {
	// Override base directory for testing
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	_ = tmpHome

	items, err := ListSealedItems()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items))
	}
}

func TestListSealedItems_MultipleSorted(t *testing.T) {
	// Override base directory for testing
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	authority := newTestDrandAuthority(1000)

	// Create multiple items with slight time delays
	// to ensure distinct creation timestamps
	var ids []string
	for i := 0; i < 3; i++ {
		id, err := CreateSealedItem(
			unlockTime,
			InputSourceStdin,
			"",
			[]byte("test data "+string(rune('A'+i))),
			authority,
		)
		if err != nil {
			t.Fatalf("failed to create item %d: %v", i, err)
		}
		ids = append(ids, id)
		time.Sleep(10 * time.Millisecond) // Ensure distinct timestamps
	}

	items, err := ListSealedItems()
	if err != nil {
		t.Fatalf("listSealedItems failed: %v", err)
	}

	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}

	// Verify sorting (oldest first)
	for i := 0; i < len(items)-1; i++ {
		if !items[i].CreatedAt.Before(items[i+1].CreatedAt) {
			t.Errorf("items not sorted: item[%d] CreatedAt=%v should be before item[%d] CreatedAt=%v",
				i, items[i].CreatedAt, i+1, items[i+1].CreatedAt)
		}
	}

	// Verify IDs match
	for i, expectedID := range ids {
		if items[i].ID != expectedID {
			t.Errorf("item[%d] ID mismatch: got %s, want %s", i, items[i].ID, expectedID)
		}
	}

	_ = tmpHome
}

func TestListingDoesNotMaterialize(t *testing.T) {
	// Setup: create a sealed item that is eligible for unlock
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	// Create item with past unlock time (eligible for unlock)
	pastTime := time.Now().UTC().Add(-1 * time.Hour)
	authority := newTestDrandAuthority(999999) // High round number (already past)
	
	plaintext := []byte("test data that should unlock")
	id, err := CreateSealedItem(pastTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("failed to create sealed item: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	itemDir := filepath.Join(baseDir, id)
	unsealedPath := filepath.Join(itemDir, "unsealed")

	// Call ListSealedItems (read-only operation)
	items, err := ListSealedItems()
	if err != nil {
		t.Fatalf("ListSealedItems failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	// Assert: item must remain sealed (no materialization happened)
	if items[0].State != StateSealed {
		t.Errorf("expected state to be sealed, got %s", items[0].State)
	}

	// Assert: unsealed file must NOT exist
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist after listing")
	}

	// Verify metadata on disk still shows sealed
	meta, err := os.ReadFile(filepath.Join(itemDir, "meta.json"))
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	if !strings.Contains(string(meta), `"state": "sealed"`) {
		t.Error("metadata should still show sealed state")
	}
}
