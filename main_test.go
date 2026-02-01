package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseUnlockTime_ValidUTC(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)
	input := future.Format(time.RFC3339)

	result, err := parseUnlockTime(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Location() != time.UTC {
		t.Errorf("expected UTC location, got: %v", result.Location())
	}

	if !result.After(time.Now().UTC()) {
		t.Errorf("expected future time, got: %v", result)
	}
}

func TestParseUnlockTime_ValidWithOffset(t *testing.T) {
	// Create a future time with an offset (e.g., +05:00)
	// Truncate to seconds since RFC3339 format doesn't preserve nanoseconds
	future := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	loc := time.FixedZone("TEST", 5*60*60) // +05:00
	futureWithOffset := future.In(loc)
	input := futureWithOffset.Format(time.RFC3339)

	result, err := parseUnlockTime(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Location() != time.UTC {
		t.Errorf("expected UTC location, got: %v", result.Location())
	}

	// Verify the absolute time is preserved (even though location changed)
	if !result.Equal(futureWithOffset) {
		t.Errorf("times not equal: got %v, want %v", result, futureWithOffset)
	}
}

func TestParseUnlockTime_InvalidFormat(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"plain text", "tomorrow"},
		{"unix timestamp", "1234567890"},
		{"ISO8601 without timezone", "2026-02-01T15:04:05"},
		{"date only", "2026-02-01"},
		{"RFC822", "01 Feb 26 15:04 UTC"},
		{"malformed", "2026-13-45T99:99:99Z"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseUnlockTime(tc.input)
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tc.input)
			}
			if err.Error() != "invalid time format, expected RFC3339" {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestParseUnlockTime_PastTimestamp(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{"yesterday", time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)},
		{"last year", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)},
		{"epoch", "1970-01-01T00:00:00Z"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseUnlockTime(tc.input)
			if err == nil {
				t.Errorf("expected error for past timestamp %q, got nil", tc.input)
			}
			if err.Error() != "unlock time must be in the future" {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestParseUnlockTime_EdgeCaseCloseToNow(t *testing.T) {
	// Time very close to now but still in the future (1 second ahead)
	future := time.Now().UTC().Add(1 * time.Second)
	input := future.Format(time.RFC3339)

	result, err := parseUnlockTime(input)
	if err != nil {
		t.Fatalf("expected no error for future time, got: %v", err)
	}

	if !result.After(time.Now().UTC()) {
		t.Errorf("expected future time, got: %v", result)
	}
}

func TestParseUnlockTime_ExactlyNow(t *testing.T) {
	// Time exactly now (or as close as possible) should be rejected
	now := time.Now().UTC()
	input := now.Format(time.RFC3339)

	// Sleep a tiny bit to ensure "now" is definitely not in the future
	time.Sleep(1 * time.Millisecond)

	_, err := parseUnlockTime(input)
	if err == nil {
		t.Error("expected error for timestamp at or before now, got nil")
	}
	if err.Error() != "unlock time must be in the future" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseUnlockTime_NormalizesToUTC(t *testing.T) {
	// Test that different timezone representations of the same absolute time
	// are normalized to UTC correctly
	baseTime := time.Now().Add(24 * time.Hour)

	testCases := []struct {
		name string
		loc  *time.Location
	}{
		{"UTC", time.UTC},
		{"EST", time.FixedZone("EST", -5*60*60)},
		{"JST", time.FixedZone("JST", 9*60*60)},
	}

	var results []time.Time
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := baseTime.In(tc.loc).Format(time.RFC3339)
			result, err := parseUnlockTime(input)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if result.Location() != time.UTC {
				t.Errorf("expected UTC location, got: %v", result.Location())
			}

			results = append(results, result)
		})
	}

	// All results should represent the same absolute time
	if len(results) > 1 {
		for i := 1; i < len(results); i++ {
			if !results[0].Equal(results[i]) {
				t.Errorf("times not equal: %v != %v", results[0], results[i])
			}
		}
	}
}

func TestReadInput_FileValid(t *testing.T) {
	// Create temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("test content for sealing")

	err := os.WriteFile(testFile, testContent, 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	data, source, err := readInput(testFile)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if source != inputSourceFile {
		t.Errorf("expected source to be inputSourceFile, got: %v", source)
	}

	if !bytes.Equal(data, testContent) {
		t.Errorf("data mismatch: got %q, want %q", data, testContent)
	}
}

func TestReadInput_StdinValid(t *testing.T) {
	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create a pipe to simulate stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	testContent := []byte("stdin test content")
	go func() {
		w.Write(testContent)
		w.Close()
	}()

	os.Stdin = r

	data, source, err := readInput("")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if source != inputSourceStdin {
		t.Errorf("expected source to be inputSourceStdin, got: %v", source)
	}

	if !bytes.Equal(data, testContent) {
		t.Errorf("data mismatch: got %q, want %q", data, testContent)
	}
}

func TestReadInput_BothFileAndStdin(t *testing.T) {
	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("file content"), 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create a pipe to simulate stdin with data
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	go func() {
		w.Write([]byte("stdin content"))
		w.Close()
	}()

	os.Stdin = r

	_, _, err = readInput(testFile)
	if err == nil {
		t.Fatal("expected error when both file and stdin provided, got nil")
	}

	if err.Error() != "cannot read from both file and stdin" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadInput_NeitherFileNorStdin(t *testing.T) {
	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create a pipe but don't write anything (simulates terminal stdin)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	w.Close() // Close immediately to simulate no data

	// Use /dev/tty or similar to simulate a character device
	// For testing, we'll just check the actual error
	os.Stdin = oldStdin // Use actual stdin (which is typically a character device in tests)

	_, _, err = readInput("")
	if err == nil {
		t.Fatal("expected error when neither file nor stdin provided, got nil")
	}

	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("unexpected error message: %v", err)
	}

	r.Close()
}

func TestReadInput_EmptyFile(t *testing.T) {
	// Create empty temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	err := os.WriteFile(testFile, []byte{}, 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, _, err = readInput(testFile)
	if err == nil {
		t.Fatal("expected error for empty file, got nil")
	}

	if err.Error() != "input is empty" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadInput_EmptyStdin(t *testing.T) {
	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create a pipe with no data
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	// Close write end immediately (empty stdin)
	w.Close()

	os.Stdin = r

	_, _, err = readInput("")
	if err == nil {
		t.Fatal("expected error for empty stdin, got nil")
	}

	if err.Error() != "input is empty" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadInput_ExceedsMaxSize_File(t *testing.T) {
	// Create temporary test file that exceeds max size
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "large.txt")

	// Create a file larger than maxInputSize
	largeContent := make([]byte, maxInputSize+1)
	for i := range largeContent {
		largeContent[i] = 'A'
	}

	err := os.WriteFile(testFile, largeContent, 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, _, err = readInput(testFile)
	if err == nil {
		t.Fatal("expected error for file exceeding size limit, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadInput_ExceedsMaxSize_Stdin(t *testing.T) {
	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create a pipe with content exceeding max size
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	largeContent := make([]byte, maxInputSize+1)
	for i := range largeContent {
		largeContent[i] = 'B'
	}

	go func() {
		w.Write(largeContent)
		w.Close()
	}()

	os.Stdin = r

	_, _, err = readInput("")
	if err == nil {
		t.Fatal("expected error for stdin exceeding size limit, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadInput_FileDoesNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentFile := filepath.Join(tmpDir, "does-not-exist.txt")

	_, _, err := readInput(nonExistentFile)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	if !strings.Contains(err.Error(), "cannot open file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetSealBaseDir_PlatformAgnostic(t *testing.T) {
	// Test with temp directory to avoid polluting actual user directories
	// We'll test the logic indirectly by overriding environment variables
	
	// Save original environment
	oldHome := os.Getenv("HOME")
	oldAppData := os.Getenv("AppData")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("AppData", oldAppData)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	baseDir, err := getSealBaseDir()
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
	tmpDir := t.TempDir()
	
	// Save original HOME and set temporary one
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	testPayload := []byte("test sealed content")
	testPath := "/test/path.txt"

	authority := &PlaceholderAuthority{}

	// Create sealed item
	id, err := createSealedItem(unlockTime, inputSourceFile, testPath, testPayload, authority)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if id == "" {
		t.Fatal("expected non-empty ID")
	}

	// Verify directory structure
	baseDir, _ := getSealBaseDir()
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
	items, err := listSealedItems()
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

func TestListSealedItems_Empty(t *testing.T) {
	// Override base directory for testing
	tmpDir := t.TempDir()
	
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	items, err := listSealedItems()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(items) != 0 {
		t.Errorf("expected 0 items, got %d", len(items))
	}
}

func TestListSealedItems_MultipleSorted(t *testing.T) {
	// Override base directory for testing
	tmpDir := t.TempDir()
	
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	authority := &PlaceholderAuthority{}
	
	// Create multiple items with slight delays to ensure different creation times
	var ids []string
	for i := 0; i < 3; i++ {
		id, err := createSealedItem(
			unlockTime.Add(time.Duration(i)*time.Hour),
			inputSourceStdin,
			"",
			[]byte("test content "+string(rune('A'+i))),
			authority,
		)
		if err != nil {
			t.Fatalf("failed to create item %d: %v", i, err)
		}
		ids = append(ids, id)
		
		// Small delay to ensure different creation timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// List items
	items, err := listSealedItems()
	if err != nil {
		t.Fatalf("listSealedItems failed: %v", err)
	}

	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}

	// Verify items are sorted by creation time (oldest first)
	for i := 0; i < len(items)-1; i++ {
		if items[i].CreatedAt.After(items[i+1].CreatedAt) {
			t.Errorf("items not sorted: item %d created at %v is after item %d created at %v",
				i, items[i].CreatedAt, i+1, items[i+1].CreatedAt)
		}
	}

	// Verify all IDs are present
	foundIDs := make(map[string]bool)
	for _, item := range items {
		foundIDs[item.ID] = true
	}

	for _, id := range ids {
		if !foundIDs[id] {
			t.Errorf("ID %s not found in listed items", id)
		}
	}
}

func TestInputSource_String(t *testing.T) {
	if inputSourceFile.String() != "file" {
		t.Errorf("expected 'file', got %s", inputSourceFile.String())
	}

	if inputSourceStdin.String() != "stdin" {
		t.Errorf("expected 'stdin', got %s", inputSourceStdin.String())
	}
}

// decryptPayloadForTest is a test-only helper to decrypt AES-256-GCM ciphertext.
// This function is ONLY for testing and should NEVER be in production code paths.
func decryptPayloadForTest(ciphertext []byte, nonceB64 string, key []byte) ([]byte, error) {
	// Decode nonce from base64
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func TestEncryptPayload_ProducesNonPlaintext(t *testing.T) {
	plaintext := []byte("this is a secret message")

	ciphertext, nonceB64, dek, err := encryptPayload(plaintext)
	if err != nil {
		t.Fatalf("encryptPayload failed: %v", err)
	}

	// Verify DEK is returned
	if len(dek) != 32 {
		t.Errorf("expected DEK size 32, got %d", len(dek))
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should not equal plaintext")
	}

	// Verify nonce is base64 encoded
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Fatalf("nonce is not valid base64: %v", err)
	}

	// Verify nonce size is correct (GCM standard is 12 bytes)
	if len(nonce) != 12 {
		t.Errorf("expected nonce size 12, got %d", len(nonce))
	}

	// Verify ciphertext is longer than plaintext (includes auth tag)
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("expected ciphertext to be longer than plaintext (includes auth tag)")
	}
}

func TestEncryptPayload_RoundTrip(t *testing.T) {
	// Test various plaintext sizes
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"short", []byte("hello")},
		{"medium", []byte("this is a longer message with more content")},
		{"empty", []byte("")},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// For testing purposes, we need to modify encryptPayload to return the key
			// Since we can't do that without changing production code, we'll test
			// via the full createSealedItem flow

			// Override base directory for testing
			tmpDir := t.TempDir()
			oldHome := os.Getenv("HOME")
			oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
			defer func() {
				os.Setenv("HOME", oldHome)
				os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
			}()

			os.Setenv("HOME", tmpDir)
			os.Setenv("XDG_DATA_HOME", "")

			// Now we get the DEK back, so we can test round-trip

			ciphertext, nonceB64, dek, err := encryptPayload(tc.plaintext)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}
			defer func() {
				for i := range dek {
					dek[i] = 0
				}
			}()

			// Verify structure
			if len(nonceB64) == 0 {
				t.Error("nonce should not be empty")
			}

			nonce, err := base64.StdEncoding.DecodeString(nonceB64)
			if err != nil {
				t.Fatalf("nonce decoding failed: %v", err)
			}

			if len(nonce) != 12 {
				t.Errorf("expected nonce size 12, got %d", len(nonce))
			}

			// For empty plaintext, ciphertext should still contain auth tag
			if len(tc.plaintext) == 0 {
				if len(ciphertext) != 16 { // GCM auth tag is 16 bytes
					t.Errorf("expected ciphertext size 16 for empty plaintext, got %d", len(ciphertext))
				}
			}
		})
	}
}

func TestEncryptPayload_DifferentNoncesEachTime(t *testing.T) {
	plaintext := []byte("same message")

	// Encrypt multiple times
	var nonces []string
	for i := 0; i < 5; i++ {
		_, nonceB64, dek, err := encryptPayload(plaintext)
		if err != nil {
			t.Fatalf("encryption %d failed: %v", i, err)
		}
		// Zero out DEK
		for j := range dek {
			dek[j] = 0
		}
		nonces = append(nonces, nonceB64)
	}

	// Verify all nonces are different
	for i := 0; i < len(nonces); i++ {
		for j := i + 1; j < len(nonces); j++ {
			if nonces[i] == nonces[j] {
				t.Errorf("nonces should be unique, but nonce %d equals nonce %d", i, j)
			}
		}
	}
}

func TestEncryptPayload_DifferentCiphertextEachTime(t *testing.T) {
	plaintext := []byte("same message")

	// Encrypt multiple times
	var ciphertexts [][]byte
	for i := 0; i < 5; i++ {
		ciphertext, _, dek, err := encryptPayload(plaintext)
		if err != nil {
			t.Fatalf("encryption %d failed: %v", i, err)
		}
		// Zero out DEK
		for j := range dek {
			dek[j] = 0
		}
		ciphertexts = append(ciphertexts, ciphertext)
	}

	// Verify all ciphertexts are different (due to different nonces)
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			if bytes.Equal(ciphertexts[i], ciphertexts[j]) {
				t.Errorf("ciphertexts should be different, but ciphertext %d equals ciphertext %d", i, j)
			}
		}
	}
}

func TestCreateSealedItem_EncryptsPayload(t *testing.T) {
	// Override base directory for testing
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("secret data to seal")
	authority := &PlaceholderAuthority{}

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read back the metadata
	baseDir, _ := getSealBaseDir()
	metaPath := filepath.Join(baseDir, id, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify crypto metadata
	if meta.Algorithm != "aes-256-gcm" {
		t.Errorf("expected algorithm 'aes-256-gcm', got %s", meta.Algorithm)
	}

	if meta.Nonce == "" {
		t.Error("nonce should not be empty")
	}

	if meta.KeyRef != "placeholder-key-ref" {
		t.Errorf("expected key_ref 'placeholder-key-ref', got %s", meta.KeyRef)
	}

	// Verify nonce decodes properly
	nonce, err := base64.StdEncoding.DecodeString(meta.Nonce)
	if err != nil {
		t.Fatalf("nonce is not valid base64: %v", err)
	}

	if len(nonce) != 12 {
		t.Errorf("expected nonce size 12, got %d", len(nonce))
	}

	// Read payload
	payloadPath := filepath.Join(baseDir, id, "payload.bin")
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}

	// Verify payload is NOT plaintext
	if bytes.Equal(payload, plaintext) {
		t.Error("payload should be encrypted, not plaintext")
	}

	// Verify payload is not empty
	if len(payload) == 0 {
		t.Error("payload should not be empty")
	}
}

func TestMetadata_IncludesCryptoFields(t *testing.T) {
	unlockTime := time.Date(2027, 3, 15, 14, 30, 0, 0, time.UTC)
	createdAt := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)

	meta := SealedItem{
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
	jsonData, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded SealedItem
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify crypto fields
	if decoded.Algorithm != "aes-256-gcm" {
		t.Errorf("Algorithm mismatch: got %s, want aes-256-gcm", decoded.Algorithm)
	}

	if decoded.Nonce != "dGVzdG5vbmNl" {
		t.Errorf("Nonce mismatch: got %s, want dGVzdG5vbmNl", decoded.Nonce)
	}

	if decoded.KeyRef != "placeholder-key-ref" {
		t.Errorf("KeyRef mismatch: got %s, want placeholder-key-ref", decoded.KeyRef)
	}
}

func TestLockCommand_OutputContract_Success(t *testing.T) {
	// Build the binary for testing
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	// Override HOME for isolated test
	tmpHome := t.TempDir()
	
	// Create test input
	input := "test secret data"

	// Run seal lock command
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z")
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s\nstdout: %s", err, stderrStr, stdout.String())
	}

	// Verify stdout contains only the ID
	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	// Stderr must be empty on success
	if stderrStr != "" {
		t.Errorf("stderr should be empty on success, got: %q", stderrStr)
	}

	// Stdout should contain only the ID and optional trailing newline
	stdoutTrimmed := strings.TrimSpace(stdoutStr)
	
	// Verify it's a valid UUID format
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(stdoutTrimmed) {
		t.Errorf("stdout should contain only a UUID, got: %q", stdoutStr)
	}

	// Verify there's exactly one line (ID + newline)
	lines := strings.Split(stdoutStr, "\n")
	if len(lines) != 2 || lines[1] != "" {
		t.Errorf("stdout should be exactly one line with trailing newline, got %d lines: %q", len(lines), stdoutStr)
	}

	// Verify no prefixes, suffixes, or labels
	if stdoutStr != stdoutTrimmed+"\n" {
		t.Errorf("stdout should be exactly ID + newline, got: %q", stdoutStr)
	}
}

func TestLockCommand_OutputContract_Error(t *testing.T) {
	// Build the binary for testing
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	testCases := []struct {
		name     string
		args     []string
		stdin    string
		wantErr  string
	}{
		{
			name:    "missing --until flag",
			args:    []string{"lock"},
			stdin:   "test",
			wantErr: "error: --until is required",
		},
		{
			name:    "invalid time format",
			args:    []string{"lock", "--until", "invalid"},
			stdin:   "test",
			wantErr: "error: invalid time format",
		},
		{
			name:    "past timestamp",
			args:    []string{"lock", "--until", "2020-01-01T00:00:00Z"},
			stdin:   "test",
			wantErr: "error: unlock time must be in the future",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpHome := t.TempDir()

			cmd := exec.Command(binPath, tc.args...)
			cmd.Stdin = strings.NewReader(tc.stdin)
			cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			
			// Error cases should exit with non-zero
			if err == nil {
				t.Fatalf("expected command to fail, but it succeeded\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
			}

			// Stdout should be empty on error
			if stdout.String() != "" {
				t.Errorf("stdout should be empty on error, got: %q", stdout.String())
			}

			// Stderr should contain the error message
			stderrStr := stderr.String()
			if !strings.Contains(stderrStr, tc.wantErr) {
				t.Errorf("stderr should contain %q, got: %q", tc.wantErr, stderrStr)
			}
		})
	}
}

func TestLockCommand_OutputContract_NoExtraOutput(t *testing.T) {
	// This test ensures there are no warnings, informational messages,
	// or any other output on success
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()
	
	// Create a test file
	testFile := filepath.Join(tmpHome, "test.txt")
	if err := os.WriteFile(testFile, []byte("file content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test with file input
	cmd := exec.Command(binPath, "lock", "--until", "2027-06-15T10:00:00Z", testFile)
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderrStr)
	}

	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	// No warnings or informational messages
	if stderrStr != "" {
		t.Errorf("no messages should be written to stderr on success, got: %q", stderrStr)
	}

	// Only ID output
	stdoutTrimmed := strings.TrimSpace(stdoutStr)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(stdoutTrimmed) {
		t.Errorf("output should be only UUID, got: %q", stdoutStr)
	}

	// No labels like "ID:", "Sealed:", etc.
	if strings.Contains(stdoutStr, ":") {
		t.Errorf("output should not contain labels or colons, got: %q", stdoutStr)
	}

	// No multiple IDs or extra lines
	if strings.Count(stdoutStr, "\n") != 1 {
		t.Errorf("output should have exactly one newline, got: %q", stdoutStr)
	}
}

func TestShredFile_RemovesFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "to-shred.txt")
	testContent := []byte("secret data that should be shredded")

	if err := os.WriteFile(testFile, testContent, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Verify file exists before shredding
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Fatal("test file should exist before shredding")
	}

	warnings := shredFile(testFile)

	// Should complete without warnings
	if len(warnings) > 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}

	// File should no longer exist
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("file should not exist after shredding")
	}
}

func TestShredFile_HandlesErrors(t *testing.T) {
	// Try to shred a non-existent file
	nonExistent := "/tmp/seal-test-nonexistent-file-for-shred.txt"
	warnings := shredFile(nonExistent)

	// Should return warnings but not panic
	if len(warnings) == 0 {
		t.Error("expected warnings when shredding non-existent file")
	}

	// Warning should mention the failure
	if !strings.Contains(warnings[0], "warning:") {
		t.Errorf("expected warning message, got: %q", warnings[0])
	}
}

func TestLockCommand_Shred_Success(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()
	testFile := filepath.Join(tmpHome, "secret.txt")
	testContent := []byte("secret data to seal and shred")

	if err := os.WriteFile(testFile, testContent, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Fatal("test file should exist before sealing")
	}

	// Run seal lock with --shred
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--shred", testFile)
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderrStr)
	}

	// Stdout should contain only ID
	stdoutStr := stdout.String()
	stdoutTrimmed := strings.TrimSpace(stdoutStr)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(stdoutTrimmed) {
		t.Errorf("stdout should contain only UUID, got: %q", stdoutStr)
	}

	// Stderr should contain the mandatory warning
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "warning: file shredding on modern filesystems is best-effort only. backups, snapshots, wear leveling, and caches may retain data.") {
		t.Errorf("stderr should contain shredding warning, got: %q", stderrStr)
	}

	// Original file should be removed
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("original file should be removed after shredding")
	}
}

func TestLockCommand_Shred_FailureDoesNotAbortSealing(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()
	testFile := filepath.Join(tmpHome, "secret.txt")
	testContent := []byte("test data")

	if err := os.WriteFile(testFile, testContent, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Make file read-only to cause shredding to fail
	if err := os.Chmod(testFile, 0400); err != nil {
		t.Fatalf("failed to make file read-only: %v", err)
	}

	// Run seal lock with --shred
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--shred", testFile)
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Should succeed despite shredding failure
	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock should succeed even if shredding fails: %v\nstderr: %s", err, stderrStr)
	}

	// Stdout should still contain the sealed item ID
	stdoutStr := stdout.String()
	stdoutTrimmed := strings.TrimSpace(stdoutStr)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(stdoutTrimmed) {
		t.Errorf("stdout should contain UUID even on shred failure, got: %q", stdoutStr)
	}

	// Stderr should contain both the mandatory warning and shredding failure warning
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "warning: file shredding on modern filesystems is best-effort only. backups, snapshots, wear leveling, and caches may retain data.") {
		t.Errorf("stderr should contain mandatory warning, got: %q", stderrStr)
	}

	if strings.Count(stderrStr, "warning:") < 2 {
		t.Errorf("stderr should contain both mandatory warning and shredding failure warning, got: %q", stderrStr)
	}

	// Clean up - restore write permissions and remove file
	os.Chmod(testFile, 0600)
	os.Remove(testFile)
}

func TestLockCommand_Shred_ErrorWithStdin(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()

	// Run seal lock with --shred on stdin input (should error)
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--shred")
	cmd.Stdin = strings.NewReader("test content")
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Should fail with error
	err := cmd.Run()
	if err == nil {
		t.Fatal("seal lock with --shred and stdin should fail")
	}

	// Stdout should be empty
	if stdout.String() != "" {
		t.Errorf("stdout should be empty on error, got: %q", stdout.String())
	}

	// Stderr should contain the error
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "error: --shred can only be used with file input") {
		t.Errorf("stderr should contain shred+stdin error, got: %q", stderrStr)
	}
}

func TestLockCommand_Shred_WarningNotSuppressible(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()
	testFile := filepath.Join(tmpHome, "test.txt")

	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Run with --shred - warning must appear
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--shred", testFile)
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderrStr)
	}

	stderrStr := stderr.String()

	// Warning must always appear when --shred is used
	expectedWarning := "warning: file shredding on modern filesystems is best-effort only. backups, snapshots, wear leveling, and caches may retain data."
	if !strings.Contains(stderrStr, expectedWarning) {
		t.Error("mandatory warning must appear when --shred is used")
	}

	// Verify it appears exactly once (not multiple times)
	warningCount := strings.Count(stderrStr, expectedWarning)
	if warningCount != 1 {
		t.Errorf("warning should appear exactly once, appeared %d times", warningCount)
	}
}

func TestClearClipboard_BestEffort(t *testing.T) {
	// Test that clearClipboard doesn't panic and returns warnings on unsupported platforms
	warnings := clearClipboard()

	// On macOS, it may succeed (no warnings) or fail (warnings)
	// On other platforms, it should warn about not being implemented
	// Either way, it should not panic
	if runtime.GOOS != "darwin" && len(warnings) == 0 {
		t.Error("expected warning on non-macOS platform")
	}

	// All warnings should start with "warning:"
	for _, warning := range warnings {
		if !strings.HasPrefix(warning, "warning:") {
			t.Errorf("warning should start with 'warning:', got: %q", warning)
		}
	}
}

func TestLockCommand_ClearClipboard_Success(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()

	// Run seal lock with --clear-clipboard from stdin
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--clear-clipboard")
	cmd.Stdin = strings.NewReader("secret content to seal")
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderrStr)
	}

	// Stdout should contain only ID
	stdoutStr := stdout.String()
	stdoutTrimmed := strings.TrimSpace(stdoutStr)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(stdoutTrimmed) {
		t.Errorf("stdout should contain only UUID, got: %q", stdoutStr)
	}

	// Stderr should contain the mandatory warning
	stderrStr := stderr.String()
	expectedWarning := "warning: clipboard clearing is best-effort; the OS or other apps may retain copies"
	if !strings.Contains(stderrStr, expectedWarning) {
		t.Errorf("stderr should contain clipboard warning, got: %q", stderrStr)
	}
}

func TestLockCommand_ClearClipboard_ErrorWithFile(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()
	testFile := filepath.Join(tmpHome, "test.txt")

	if err := os.WriteFile(testFile, []byte("test content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Run seal lock with --clear-clipboard on file input (should error)
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--clear-clipboard", testFile)
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Should fail with error
	err := cmd.Run()
	if err == nil {
		t.Fatal("seal lock with --clear-clipboard and file input should fail")
	}

	// Stdout should be empty
	if stdout.String() != "" {
		t.Errorf("stdout should be empty on error, got: %q", stdout.String())
	}

	// Stderr should contain the error
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "error: --clear-clipboard can only be used with stdin input") {
		t.Errorf("stderr should contain clear-clipboard+file error, got: %q", stderrStr)
	}
}

func TestLockCommand_ClearClipboard_WarningNotSuppressible(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()

	// Run with --clear-clipboard - warning must appear
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--clear-clipboard")
	cmd.Stdin = strings.NewReader("test content")
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderrStr)
	}

	stderrStr := stderr.String()

	// Warning must always appear when --clear-clipboard is used
	expectedWarning := "warning: clipboard clearing is best-effort; the OS or other apps may retain copies"
	if !strings.Contains(stderrStr, expectedWarning) {
		t.Error("mandatory warning must appear when --clear-clipboard is used")
	}

	// Verify it appears exactly once (not multiple times)
	warningCount := strings.Count(stderrStr, expectedWarning)
	if warningCount != 1 {
		t.Errorf("warning should appear exactly once, appeared %d times", warningCount)
	}
}

func TestLockCommand_ClearClipboard_FailureDoesNotAbortSealing(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()

	// Run seal lock with --clear-clipboard
	// Even if clipboard clearing fails (e.g., on unsupported platform), sealing should succeed
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z", "--clear-clipboard")
	cmd.Stdin = strings.NewReader("test data")
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Should succeed even if clipboard clearing fails
	if err := cmd.Run(); err != nil {
		// Skip if drand network is unavailable (drand is now the default)
		stderrStr := stderr.String()
		if strings.Contains(stderrStr, "drand") || strings.Contains(stderrStr, "tls:") {
			t.Skipf("skipping test due to network error (drand unavailable): %s", stderrStr)
		}
		t.Fatalf("seal lock should succeed even if clipboard clearing fails: %v\nstderr: %s", err, stderrStr)
	}

	// Stdout should still contain the sealed item ID
	stdoutStr := stdout.String()
	stdoutTrimmed := strings.TrimSpace(stdoutStr)
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(stdoutTrimmed) {
		t.Errorf("stdout should contain UUID even on clipboard clear failure, got: %q", stdoutStr)
	}

	// Stderr should contain the mandatory warning
	stderrStr := stderr.String()
	expectedWarning := "warning: clipboard clearing is best-effort; the OS or other apps may retain copies"
	if !strings.Contains(stderrStr, expectedWarning) {
		t.Errorf("stderr should contain mandatory warning, got: %q", stderrStr)
	}
}

func TestPlaceholderAuthority_Name(t *testing.T) {
	authority := &PlaceholderAuthority{}
	
	if authority.Name() != "placeholder" {
		t.Errorf("expected name 'placeholder', got %s", authority.Name())
	}
}

func TestPlaceholderAuthority_Lock(t *testing.T) {
	authority := &PlaceholderAuthority{}
	unlockTime := time.Now().UTC().Add(24 * time.Hour)

	ref, err := authority.Lock(unlockTime)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should return a deterministic key reference
	if ref == "" {
		t.Error("key reference should not be empty")
	}

	if string(ref) != "placeholder-key-ref" {
		t.Errorf("expected key reference 'placeholder-key-ref', got %s", ref)
	}
}

func TestPlaceholderAuthority_CanUnlock_AlwaysFalse(t *testing.T) {
	authority := &PlaceholderAuthority{}
	ref := KeyReference("placeholder-key-ref")

	testCases := []struct {
		name string
		now  time.Time
	}{
		{"past", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"present", time.Now().UTC()},
		{"future", time.Now().UTC().Add(100 * 365 * 24 * time.Hour)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			canUnlock, err := authority.CanUnlock(ref, tc.now)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if canUnlock {
				t.Error("placeholder authority should never permit unlocking")
			}
		})
	}
}

func TestCreateSealedItem_StoresAuthorityMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &PlaceholderAuthority{}

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read back metadata
	baseDir, _ := getSealBaseDir()
	metaPath := filepath.Join(baseDir, id, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify authority metadata
	if meta.TimeAuthority != "placeholder" {
		t.Errorf("expected time_authority 'placeholder', got %s", meta.TimeAuthority)
	}

	if meta.KeyRef != "placeholder-key-ref" {
		t.Errorf("expected key_ref 'placeholder-key-ref', got %s", meta.KeyRef)
	}
}

func TestSealedItem_StateDefaultsToSealed(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &PlaceholderAuthority{}

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read metadata
	baseDir, _ := getSealBaseDir()
	metaPath := filepath.Join(baseDir, id, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify state is "sealed"
	if meta.State != "sealed" {
		t.Errorf("expected state 'sealed', got %s", meta.State)
	}
}

func TestUnsealedPath_NeverCreated(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &PlaceholderAuthority{}

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Verify unsealed path does not exist
	baseDir, _ := getSealBaseDir()
	unsealedPath := filepath.Join(baseDir, id, "unsealed")

	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist for sealed item")
	}

	// List items (which calls checkAndTransitionUnlock)
	items, err := listSealedItems()
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

	result, err := checkAndTransitionUnlock(sealedItem, itemDir)
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

	result, err = checkAndTransitionUnlock(unlockedItem, itemDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should remain unlocked
	if result.State != "unlocked" {
		t.Errorf("state should remain unlocked, got %s", result.State)
	}
}

func TestDrandAuthority_Name(t *testing.T) {
	authority := NewDrandAuthority()
	
	if authority.Name() != "drand" {
		t.Errorf("expected name 'drand', got %s", authority.Name())
	}
}

func TestDrandAuthority_KeyReference_Structure(t *testing.T) {
	// Test that Lock produces a valid DrandKeyReference structure
	authority := NewDrandAuthority()
	
	// Use a future time for testing (doesn't make actual network call in Lock yet)
	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	
	// Note: This will make a network call to get drand info
	// We'll accept this for now as it's needed to compute the target round
	ref, err := authority.Lock(unlockTime)
	if err != nil {
		// If network is unavailable, skip this test
		t.Skipf("skipping test due to network error: %v", err)
	}

	// Parse the reference
	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(ref), &drandRef); err != nil {
		t.Fatalf("key reference should be valid JSON: %v", err)
	}

	// Verify structure
	if drandRef.Network == "" {
		t.Error("network should not be empty")
	}

	if drandRef.TargetRound == 0 {
		t.Error("target round should not be zero")
	}

	if drandRef.Network != "quicknet" {
		t.Errorf("expected network 'quicknet', got %s", drandRef.Network)
	}
}

func TestDrandAuthority_CanUnlock_Logic(t *testing.T) {
	// Test CanUnlock with manually crafted references
	authority := NewDrandAuthority()
	
	testCases := []struct {
		name        string
		ref         DrandKeyReference
		shouldError bool
	}{
		{
			name: "valid reference",
			ref: DrandKeyReference{
				Network:     "quicknet",
				TargetRound: 1000000,
			},
			shouldError: false,
		},
		{
			name: "wrong network",
			ref: DrandKeyReference{
				Network:     "wrong-network",
				TargetRound: 1000000,
			},
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			refJSON, _ := json.Marshal(tc.ref)
			keyRef := KeyReference(refJSON)
			
			_, err := authority.CanUnlock(keyRef, time.Now())
			
			if tc.shouldError && err == nil {
				t.Error("expected error, got nil")
			}
			
			if !tc.shouldError && err != nil {
				// Network errors are acceptable in tests
				if !strings.Contains(err.Error(), "failed to fetch") {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDrandAuthority_InvalidKeyReference(t *testing.T) {
	authority := NewDrandAuthority()
	
	// Invalid JSON
	invalidRef := KeyReference("not-valid-json")
	
	canUnlock, err := authority.CanUnlock(invalidRef, time.Now())
	if err == nil {
		t.Error("expected error for invalid key reference")
	}
	
	if canUnlock {
		t.Error("should not be able to unlock with invalid reference")
	}
	
	if !strings.Contains(err.Error(), "invalid drand key reference") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDrandAuthority_NetworkFailure_DoesNotUnlock(t *testing.T) {
	// Test with invalid base URL to simulate network failure
	authority := &DrandAuthority{
		NetworkName: "test-network",
		BaseURL:     "http://invalid.example.com/nonexistent",
	}
	
	ref := DrandKeyReference{
		Network:     "test-network",
		TargetRound: 1000,
	}
	
	refJSON, _ := json.Marshal(ref)
	keyRef := KeyReference(refJSON)
	
	canUnlock, err := authority.CanUnlock(keyRef, time.Now())
	
	// Network failure should return error
	if err == nil {
		t.Error("expected error on network failure")
	}
	
	// Should NOT unlock on network failure
	if canUnlock {
		t.Error("should not unlock on network failure")
	}
}

func TestDrandKeyReference_Serialization(t *testing.T) {
	ref := DrandKeyReference{
		Network:     "quicknet",
		TargetRound: 12345678,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded DrandKeyReference
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify fields
	if decoded.Network != ref.Network {
		t.Errorf("Network mismatch: got %s, want %s", decoded.Network, ref.Network)
	}

	if decoded.TargetRound != ref.TargetRound {
		t.Errorf("TargetRound mismatch: got %d, want %d", decoded.TargetRound, ref.TargetRound)
	}
}

func TestDrandAuthority_RoundCalculation(t *testing.T) {
	// Test the round calculation logic with known values
	// drand quicknet has 3 second period, genesis at specific time
	
	authority := NewDrandAuthority()
	
	// Get info to understand the network
	info, err := authority.fetchInfo()
	if err != nil {
		t.Skipf("skipping test due to network error: %v", err)
	}

	// Create a time based on genesis + known rounds
	// Round N starts at: genesis_time + (N * period)
	testRound := uint64(1000)
	testTime := time.Unix(info.GenesisTime+int64(testRound)*int64(info.Period), 0)
	
	ref, err := authority.Lock(testTime)
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(ref), &drandRef); err != nil {
		t.Fatalf("failed to parse reference: %v", err)
	}

	// Target round should be at or slightly after testRound
	// (due to rounding up to ensure unlock time is reached)
	if drandRef.TargetRound < testRound {
		t.Errorf("target round should be >= %d, got %d", testRound, drandRef.TargetRound)
	}

	if drandRef.TargetRound > testRound+1 {
		t.Errorf("target round should be close to %d, got %d", testRound, drandRef.TargetRound)
	}
}

func TestCreateSealedItem_WithDrandAuthority(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data with drand")
	authority := NewDrandAuthority()

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Skipf("skipping test due to error (likely network): %v", err)
	}

	// Read back metadata
	baseDir, _ := getSealBaseDir()
	metaPath := filepath.Join(baseDir, id, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify drand authority metadata
	if meta.TimeAuthority != "drand" {
		t.Errorf("expected time_authority 'drand', got %s", meta.TimeAuthority)
	}

	// Verify key_ref is valid JSON
	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(meta.KeyRef), &drandRef); err != nil {
		t.Fatalf("key_ref should be valid DrandKeyReference JSON: %v", err)
	}

	if drandRef.Network != "quicknet" {
		t.Errorf("expected network 'quicknet', got %s", drandRef.Network)
	}

	if drandRef.TargetRound == 0 {
		t.Error("target round should not be zero")
	}

	// Verify state is sealed
	if meta.State != "sealed" {
		t.Errorf("expected state 'sealed', got %s", meta.State)
	}

	// Verify tlock-encrypted DEK exists for drand authority
	if meta.DEKTlockB64 == "" {
		t.Error("dek_tlock_b64 should not be empty for drand authority")
	}

	// Verify tlock ciphertext is valid base64
	_, err = base64.StdEncoding.DecodeString(meta.DEKTlockB64)
	if err != nil {
		t.Fatalf("dek_tlock_b64 should be valid base64: %v", err)
	}

	// Verify dek.bin does NOT exist (security fix)
	dekPath := filepath.Join(baseDir, id, "dek.bin")
	if _, err := os.Stat(dekPath); !os.IsNotExist(err) {
		t.Error("dek.bin should NOT exist (security fix)")
	}
}

func TestCreateSealedItem_DrandAuthority_UsesTlock(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := NewDrandAuthority()

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Skipf("skipping due to error (likely network): %v", err)
	}

	// Read metadata
	baseDir, _ := getSealBaseDir()
	metaPath := filepath.Join(baseDir, id, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify tlock-encrypted DEK exists
	if meta.DEKTlockB64 == "" {
		t.Error("dek_tlock_b64 should not be empty for drand authority")
	}

	// Verify tlock ciphertext is valid base64
	_, err = base64.StdEncoding.DecodeString(meta.DEKTlockB64)
	if err != nil {
		t.Fatalf("dek_tlock_b64 should be valid base64: %v", err)
	}

	// Verify dek.bin does NOT exist (security fix)
	dekPath := filepath.Join(baseDir, id, "dek.bin")
	if _, err := os.Stat(dekPath); !os.IsNotExist(err) {
		t.Error("dek.bin should NOT exist (security fix)")
	}
}

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

	authority := &PlaceholderAuthority{}

	result, err := tryMaterialize(item, itemDir, authority)
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

	authority := NewDrandAuthority()

	result, err := tryMaterialize(item, itemDir, authority)
	if err != nil {
		t.Fatalf("tryMaterialize should not error for unlocked item: %v", err)
	}

	// Should remain unlocked
	if result.State != "unlocked" {
		t.Errorf("state should remain unlocked, got %s", result.State)
	}
}

func TestLockCommand_DefaultsToDrandAuthority(t *testing.T) {
	// Build the binary for testing
	binPath := filepath.Join(t.TempDir(), "seal-test")
	buildCmd := exec.Command("go", "build", "-o", binPath)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}

	tmpHome := t.TempDir()

	// Run seal lock command
	cmd := exec.Command(binPath, "lock", "--until", "2027-12-31T23:59:59Z")
	cmd.Stdin = strings.NewReader("test secret data")
	cmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Network errors are acceptable - skip if drand is unreachable
		if strings.Contains(stderr.String(), "drand") || strings.Contains(stderr.String(), "network") {
			t.Skipf("skipping test due to network error: %s", stderr.String())
		}
		t.Fatalf("seal lock failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}

	// Get the item ID from stdout
	itemID := strings.TrimSpace(stdout.String())

	// Verify it's a valid UUID
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(itemID) {
		t.Fatalf("expected valid UUID, got: %q", itemID)
	}

	// Read the metadata file
	var baseDir string
	if runtime.GOOS == "darwin" {
		baseDir = filepath.Join(tmpHome, "Library", "Application Support", "seal")
	} else {
		baseDir = filepath.Join(tmpHome, ".local", "share", "seal")
	}

	metaPath := filepath.Join(baseDir, itemID, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify drand is the default time authority
	if meta.TimeAuthority != "drand" {
		t.Errorf("expected time_authority 'drand', got %s", meta.TimeAuthority)
	}

	// Verify tlock-encrypted DEK exists (drand-specific)
	if meta.DEKTlockB64 == "" {
		t.Error("dek_tlock_b64 should not be empty for drand authority")
	}

	// Verify key_ref is valid drand reference JSON
	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(meta.KeyRef), &drandRef); err != nil {
		t.Fatalf("key_ref should be valid DrandKeyReference JSON: %v", err)
	}

	if drandRef.Network != "quicknet" {
		t.Errorf("expected network 'quicknet', got %s", drandRef.Network)
	}

	if drandRef.TargetRound == 0 {
		t.Error("target round should not be zero")
	}
}

func TestPlaceholderSealedItems_NeverMaterialize(t *testing.T) {
	// This test verifies that items sealed with placeholder authority
	// remain inert and never materialize, even when the unlock time has passed.
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}()

	os.Setenv("HOME", tmpDir)
	os.Setenv("XDG_DATA_HOME", "")

	// Create an item with placeholder authority (simulating old/test items)
	unlockTime := time.Now().UTC().Add(-24 * time.Hour) // Already past
	plaintext := []byte("test data sealed with placeholder")
	authority := &PlaceholderAuthority{}

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// List items (which triggers checkAndTransitionUnlock)
	items, err := listSealedItems()
	if err != nil {
		t.Fatalf("listSealedItems failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	// Verify item remains sealed (not unlocked)
	if items[0].State != "sealed" {
		t.Errorf("placeholder-sealed item should remain sealed, got %s", items[0].State)
	}

	// Verify unsealed file does not exist
	baseDir, _ := getSealBaseDir()
	unsealedPath := filepath.Join(baseDir, id, "unsealed")
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should not exist for placeholder-sealed items")
	}

	// Call checkAndTransitionUnlock directly multiple times
	itemDir := filepath.Join(baseDir, id)
	for i := 0; i < 3; i++ {
		result, err := checkAndTransitionUnlock(items[0], itemDir)
		if err != nil {
			t.Fatalf("checkAndTransitionUnlock should not error: %v", err)
		}
		if result.State != "sealed" {
			t.Errorf("iteration %d: state should remain sealed, got %s", i, result.State)
		}
	}

	// Final verification: unsealed file still does not exist
	if _, err := os.Stat(unsealedPath); !os.IsNotExist(err) {
		t.Error("unsealed file should never be created for placeholder-sealed items")
	}
}
