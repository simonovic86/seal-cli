package seal

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

	"seal/internal/testutil"
	"seal/internal/timeauth"
)

func TestParseUnlockTime_ValidUTC(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)
	input := future.Format(time.RFC3339)

	result, err := ParseUnlockTime(input)
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

	result, err := ParseUnlockTime(input)
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
			_, err := ParseUnlockTime(tc.input)
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
			_, err := ParseUnlockTime(tc.input)
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

	result, err := ParseUnlockTime(input)
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

	_, err := ParseUnlockTime(input)
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
			result, err := ParseUnlockTime(input)
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

	data, source, err := ReadInput(testFile)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if source != InputSourceFile {
		t.Errorf("expected source to be InputSourceFile, got: %v", source)
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

	data, source, err := ReadInput("")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if source != InputSourceStdin {
		t.Errorf("expected source to be InputSourceStdin, got: %v", source)
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

	_, _, err = ReadInput(testFile)
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

	// Use actual stdin (which is typically a character device in tests)
	os.Stdin = oldStdin

	_, _, err := ReadInput("")
	if err == nil {
		t.Fatal("expected error when neither file nor stdin provided, got nil")
	}

	if !strings.Contains(err.Error(), "no input provided") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestReadInput_EmptyFile(t *testing.T) {
	// Create empty temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	err := os.WriteFile(testFile, []byte{}, 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, _, err = ReadInput(testFile)
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

	_, _, err = ReadInput("")
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

	// Create a file larger than MaxInputSize
	largeContent := make([]byte, MaxInputSize+1)
	for i := range largeContent {
		largeContent[i] = 'A'
	}

	err := os.WriteFile(testFile, largeContent, 0600)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, _, err = ReadInput(testFile)
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

	largeContent := make([]byte, MaxInputSize+1)
	for i := range largeContent {
		largeContent[i] = 'B'
	}

	go func() {
		w.Write(largeContent)
		w.Close()
	}()

	os.Stdin = r

	_, _, err = ReadInput("")
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

	_, _, err := ReadInput(nonExistentFile)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	if !strings.Contains(err.Error(), "cannot open file") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestInputSource_String(t *testing.T) {
	if InputSourceFile.String() != "file" {
		t.Errorf("expected 'file', got %s", InputSourceFile.String())
	}

	if InputSourceStdin.String() != "stdin" {
		t.Errorf("expected 'stdin', got %s", InputSourceStdin.String())
	}
}

func TestEncryptPayload_ProducesNonPlaintext(t *testing.T) {
	plaintext := []byte("secret data that should be encrypted")

	ciphertext, nonceB64, dek, err := EncryptPayload(plaintext)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	// Ciphertext should not equal plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should not equal plaintext")
	}

	// Nonce should be valid base64
	_, err = base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		t.Errorf("nonce should be valid base64: %v", err)
	}

	// DEK should be 32 bytes (AES-256)
	if len(dek) != 32 {
		t.Errorf("DEK should be 32 bytes, got %d", len(dek))
	}

	// Ciphertext should be longer than plaintext (GCM adds authentication tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext (includes auth tag)")
	}
}

func TestEncryptPayload_RoundTrip(t *testing.T) {
	// Test encryption and decryption
	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"short text", []byte("hello")},
		{"long text", []byte(strings.Repeat("a", 1000))},
		{"binary data", []byte{0x00, 0x01, 0xFF, 0xFE, 0x42}},
		{"empty", []byte("")},
		{"unicode", []byte("Hello 世界 🔒")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// For testing purposes, we need to modify encryptPayload to return the key
			// In practice, the DEK is time-locked and not directly usable,
			// but for this unit test we can verify the encryption/decryption logic
			// via the full CreateSealedItem flow

			ciphertext, nonceB64, dek, err := EncryptPayload(tc.plaintext)
			if err != nil {
				t.Fatalf("EncryptPayload failed: %v", err)
			}

			// Decode nonce
			nonce, err := base64.StdEncoding.DecodeString(nonceB64)
			if err != nil {
				t.Fatalf("failed to decode nonce: %v", err)
			}

			// Decrypt using AES-256-GCM
			block, err := aes.NewCipher(dek)
			if err != nil {
				t.Fatalf("failed to create cipher: %v", err)
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("failed to create GCM: %v", err)
			}

			decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("decrypted data mismatch: got %q, want %q", decrypted, tc.plaintext)
			}
		})
	}
}

func TestEncryptPayload_DifferentNoncesEachTime(t *testing.T) {
	plaintext := []byte("test data")

	// Generate multiple nonces
	nonces := make([]string, 5)
	for i := range nonces {
		_, nonceB64, dek, err := EncryptPayload(plaintext)
		if err != nil {
			t.Fatalf("EncryptPayload failed: %v", err)
		}
		nonces[i] = nonceB64
		// Zero out DEK
		for j := range dek {
			dek[j] = 0
		}
	}

	// Verify all nonces are unique
	for i := 0; i < len(nonces); i++ {
		for j := i + 1; j < len(nonces); j++ {
			if nonces[i] == nonces[j] {
				t.Errorf("nonces should be unique, but nonce[%d] == nonce[%d]", i, j)
			}
		}
	}
}

func TestEncryptPayload_DifferentCiphertextEachTime(t *testing.T) {
	plaintext := []byte("test data")

	// Generate multiple ciphertexts
	ciphertexts := make([][]byte, 5)
	for i := range ciphertexts {
		ciphertext, _, dek, err := EncryptPayload(plaintext)
		if err != nil {
			t.Fatalf("EncryptPayload failed: %v", err)
		}
		ciphertexts[i] = ciphertext
		// Zero out DEK
		for j := range dek {
			dek[j] = 0
		}
	}

	// Verify all ciphertexts are unique (due to random nonces)
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			if bytes.Equal(ciphertexts[i], ciphertexts[j]) {
				t.Errorf("ciphertexts should be unique, but ciphertext[%d] == ciphertext[%d]", i, j)
			}
		}
	}
}

func TestShredFile_RemovesFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "toshred.txt")
	testContent := []byte("sensitive data to shred")

	if err := os.WriteFile(testFile, testContent, 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	warnings := ShredFile(testFile)

	// Should have no warnings on success
	if len(warnings) > 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}

	// File should be removed
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("file should be removed after shredding")
	}
}

func TestShredFile_HandlesErrors(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist.txt")

	warnings := ShredFile(nonExistent)

	// Should return warnings for non-existent file
	if len(warnings) == 0 {
		t.Error("expected warnings for non-existent file")
	}
}

func TestClearClipboard_BestEffort(t *testing.T) {
	// Test that clearClipboard doesn't panic and returns warnings on unsupported platforms
	warnings := ClearClipboard()

	// On macOS it might succeed (no warnings) or fail (with warnings)
	// On other platforms it should return a warning about not being implemented
	// We just verify it doesn't crash
	_ = warnings
}

func TestCreateSealedItem_StoresAuthorityMetadata(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &timeauth.PlaceholderAuthority{}

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read back metadata
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

	// Verify authority metadata
	if meta.TimeAuthority != "placeholder" {
		t.Errorf("expected time_authority 'placeholder', got %s", meta.TimeAuthority)
	}

	if meta.KeyRef != "placeholder-key-ref" {
		t.Errorf("expected key_ref 'placeholder-key-ref', got %s", meta.KeyRef)
	}
}

func TestSealedItem_StateDefaultsToSealed(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := &timeauth.PlaceholderAuthority{}

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read metadata
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

	// Verify state is "sealed"
	if meta.State != "sealed" {
		t.Errorf("expected state 'sealed', got %s", meta.State)
	}
}

func TestCreateSealedItem_EncryptsPayload(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("sensitive data to encrypt")
	authority := &timeauth.PlaceholderAuthority{}

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read payload
	baseDir := filepath.Join(tmpHome, "Library", "Application Support", "seal")
	payloadPath := filepath.Join(baseDir, id, "payload.bin")
	payloadData, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}

	// Payload should NOT be plaintext
	if bytes.Equal(payloadData, plaintext) {
		t.Error("payload should be encrypted, not plaintext")
	}
}

func TestCreateSealedItem_WithDrandAuthority(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data with drand")
	authority := newTestDrandAuthority(1000)

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read back metadata
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

	// Verify drand authority metadata
	if meta.TimeAuthority != "drand" {
		t.Errorf("expected time_authority 'drand', got %s", meta.TimeAuthority)
	}

	// Verify key_ref is valid JSON
	var drandRef timeauth.DrandKeyReference
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

	// Verify it's a fake tlock ciphertext (from FakeTimelockBox)
	if !strings.HasPrefix(meta.DEKTlockB64, "FAKE_TLOCK:") {
		t.Errorf("expected fake tlock prefix, got: %s", meta.DEKTlockB64[:20])
	}

	// Verify dek.bin does NOT exist (security fix)
	dekPath := filepath.Join(baseDir, id, "dek.bin")
	if _, err := os.Stat(dekPath); !os.IsNotExist(err) {
		t.Error("dek.bin should NOT exist (security fix)")
	}
}

func TestCreateSealedItem_DrandAuthority_UsesTlock(t *testing.T) {
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()

	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	plaintext := []byte("test data")
	authority := newTestDrandAuthority(1000)

	id, err := CreateSealedItem(unlockTime, InputSourceStdin, "", plaintext, authority)
	if err != nil {
		t.Fatalf("createSealedItem failed: %v", err)
	}

	// Read metadata
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

	// Verify tlock-encrypted DEK exists
	if meta.DEKTlockB64 == "" {
		t.Error("dek_tlock_b64 should not be empty for drand authority")
	}

	// Verify it's a fake tlock ciphertext (from FakeTimelockBox)
	if !strings.HasPrefix(meta.DEKTlockB64, "FAKE_TLOCK:") {
		t.Errorf("expected fake tlock prefix, got: %s", meta.DEKTlockB64[:20])
	}

	// Verify dek.bin does NOT exist (security fix)
	dekPath := filepath.Join(baseDir, id, "dek.bin")
	if _, err := os.Stat(dekPath); !os.IsNotExist(err) {
		t.Error("dek.bin should NOT exist (security fix)")
	}
}
