package seal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"seal/internal/testutil"
	"seal/internal/timeauth"
)

func TestGetSealBaseDir_PlatformAgnostic(t *testing.T) {
	// Test with temp directory to avoid polluting actual user directories
	// We'll test the logic indirectly by overriding environment variables
	
	_, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	baseDir, err := GetSealBaseDir()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify it ends with "seal"
	if filepath.Base(baseDir) != "seal" {
		t.Errorf("expected base dir to end with 'seal', got: %s", baseDir)
	}

	// Verify it's an absolute path
	if !filepath.IsAbs(baseDir) {
		t.Errorf("expected absolute path, got: %s", baseDir)
	}
}

func TestCreateSealedItem_And_List(t *testing.T) {
	// Override base directory for testing
	_, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	testPayload := []byte("test sealed content")
	testPath := "/test/path.txt"

	authority := &timeauth.PlaceholderAuthority{}

	// Create sealed item
	id, err := CreateSealedItem(unlockTime, InputSourceFile, testPath, testPayload, authority)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if id == "" {
		t.Fatal("expected non-empty ID")
	}

	// Verify directory structure
	baseDir, _ := GetSealBaseDir()
	itemDir := filepath.Join(baseDir, id)

	// Check item directory exists
	if _, err := os.Stat(itemDir); os.IsNotExist(err) {
		t.Fatalf("item directory does not exist: %s", itemDir)
	}

	// Check meta.json exists and is valid
	metaPath := filepath.Join(itemDir, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("cannot read meta.json: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("cannot unmarshal meta.json: %v", err)
	}

	// Verify metadata fields
	if meta.ID != id {
		t.Errorf("ID mismatch: got %s, want %s", meta.ID, id)
	}

	if !meta.UnlockTime.Equal(unlockTime) {
		t.Errorf("UnlockTime mismatch: got %v, want %v", meta.UnlockTime, unlockTime)
	}

	if meta.InputType != "file" {
		t.Errorf("InputType mismatch: got %s, want file", meta.InputType)
	}

	if meta.OriginalPath != testPath {
		t.Errorf("OriginalPath mismatch: got %s, want %s", meta.OriginalPath, testPath)
	}

	if meta.TimeAuthority != "placeholder" {
		t.Errorf("TimeAuthority mismatch: got %s, want placeholder", meta.TimeAuthority)
	}

	if meta.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}

	// Verify crypto metadata
	if meta.Algorithm != "aes-256-gcm" {
		t.Errorf("Algorithm mismatch: got %s, want aes-256-gcm", meta.Algorithm)
	}

	if meta.Nonce == "" {
		t.Error("Nonce should not be empty")
	}

	if meta.KeyRef != "placeholder-key-ref" {
		t.Errorf("KeyRef mismatch: got %s, want placeholder-key-ref", meta.KeyRef)
	}

	// Check payload.bin exists and is encrypted
	payloadPath := filepath.Join(itemDir, "payload.bin")
	payloadData, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("cannot read payload.bin: %v", err)
	}

	// Payload should be encrypted, not plaintext
	if bytes.Equal(payloadData, testPayload) {
		t.Error("payload should be encrypted, not plaintext")
	}

	if len(payloadData) == 0 {
		t.Error("payload should not be empty")
	}

	// List sealed items
	items, err := ListSealedItems()
	if err != nil {
		t.Fatalf("listSealedItems failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	if items[0].ID != id {
		t.Errorf("listed item ID mismatch: got %s, want %s", items[0].ID, id)
	}
}

func TestMetadata_RoundTrip(t *testing.T) {
	// Test JSON serialization/deserialization
	unlockTime := time.Date(2027, 3, 15, 14, 30, 0, 0, time.UTC)
	createdAt := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)

	original := SealedItem{
		ID:            "test-id-123",
		State:         "sealed",
		UnlockTime:    unlockTime,
		InputType:     "stdin",
		OriginalPath:  "",
		TimeAuthority: "placeholder",
		CreatedAt:     createdAt,
		Algorithm:     "aes-256-gcm",
		Nonce:         "dGVzdG5vbmNl",
		KeyRef:        "placeholder-key-ref",
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded SealedItem
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify all fields
	if decoded.ID != original.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, original.ID)
	}

	if decoded.State != original.State {
		t.Errorf("State mismatch: got %s, want %s", decoded.State, original.State)
	}

	if !decoded.UnlockTime.Equal(original.UnlockTime) {
		t.Errorf("UnlockTime mismatch: got %v, want %v", decoded.UnlockTime, original.UnlockTime)
	}

	if decoded.InputType != original.InputType {
		t.Errorf("InputType mismatch: got %s, want %s", decoded.InputType, original.InputType)
	}

	if decoded.OriginalPath != original.OriginalPath {
		t.Errorf("OriginalPath mismatch: got %s, want %s", decoded.OriginalPath, original.OriginalPath)
	}

	if decoded.TimeAuthority != original.TimeAuthority {
		t.Errorf("TimeAuthority mismatch: got %s, want %s", decoded.TimeAuthority, original.TimeAuthority)
	}

	if !decoded.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt mismatch: got %v, want %v", decoded.CreatedAt, original.CreatedAt)
	}

	if decoded.Algorithm != original.Algorithm {
		t.Errorf("Algorithm mismatch: got %s, want %s", decoded.Algorithm, original.Algorithm)
	}

	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce mismatch: got %s, want %s", decoded.Nonce, original.Nonce)
	}

	if decoded.KeyRef != original.KeyRef {
		t.Errorf("KeyRef mismatch: got %s, want %s", decoded.KeyRef, original.KeyRef)
	}
}

func TestMetadata_IncludesCryptoFields(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &timeauth.PlaceholderAuthority{}

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	metaPath := filepath.Join(baseDir, id, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify crypto fields exist
	if meta.Algorithm == "" {
		t.Error("algorithm should not be empty")
	}

	if meta.Nonce == "" {
		t.Error("nonce should not be empty")
	}

	// Nonce should be valid base64
	_, err = base64.StdEncoding.DecodeString(meta.Nonce)
	if err != nil {
		t.Errorf("nonce should be valid base64: %v", err)
	}
}
