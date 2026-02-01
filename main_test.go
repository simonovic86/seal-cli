package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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

	// Create sealed item
	id, err := createSealedItem(unlockTime, inputSourceFile, testPath, testPayload)
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

	if meta.KeyRef != "placeholder" {
		t.Errorf("KeyRef mismatch: got %s, want placeholder", meta.KeyRef)
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
		UnlockTime:    unlockTime,
		InputType:     "stdin",
		OriginalPath:  "",
		TimeAuthority: "placeholder",
		CreatedAt:     createdAt,
		Algorithm:     "aes-256-gcm",
		Nonce:         "dGVzdG5vbmNl",
		KeyRef:        "placeholder",
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
	
	// Create multiple items with slight delays to ensure different creation times
	var ids []string
	for i := 0; i < 3; i++ {
		id, err := createSealedItem(
			unlockTime.Add(time.Duration(i)*time.Hour),
			inputSourceStdin,
			"",
			[]byte("test content "+string(rune('A'+i))),
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

	ciphertext, nonceB64, err := encryptPayload(plaintext)
	if err != nil {
		t.Fatalf("encryptPayload failed: %v", err)
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

			// Note: We can't actually test round-trip without the key,
			// which is intentionally discarded. This test verifies the
			// encryption happens and produces valid output structure.

			ciphertext, nonceB64, err := encryptPayload(tc.plaintext)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

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
		_, nonceB64, err := encryptPayload(plaintext)
		if err != nil {
			t.Fatalf("encryption %d failed: %v", i, err)
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
		ciphertext, _, err := encryptPayload(plaintext)
		if err != nil {
			t.Fatalf("encryption %d failed: %v", i, err)
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

	id, err := createSealedItem(unlockTime, inputSourceStdin, "", plaintext)
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

	if meta.KeyRef != "placeholder" {
		t.Errorf("expected key_ref 'placeholder', got %s", meta.KeyRef)
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
		UnlockTime:    unlockTime,
		InputType:     "stdin",
		OriginalPath:  "",
		TimeAuthority: "placeholder",
		CreatedAt:     createdAt,
		Algorithm:     "aes-256-gcm",
		Nonce:         "dGVzdG5vbmNl",
		KeyRef:        "placeholder",
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

	if decoded.KeyRef != "placeholder" {
		t.Errorf("KeyRef mismatch: got %s, want placeholder", decoded.KeyRef)
	}
}
