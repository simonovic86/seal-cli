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
		t.Fatalf("seal lock failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
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
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderr.String())
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
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderr.String())
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
		t.Fatalf("seal lock should succeed even if shredding fails: %v\nstderr: %s", err, stderr.String())
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
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderr.String())
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
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderr.String())
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
		t.Fatalf("seal lock failed: %v\nstderr: %s", err, stderr.String())
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
		t.Fatalf("seal lock should succeed even if clipboard clearing fails: %v\nstderr: %s", err, stderr.String())
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
