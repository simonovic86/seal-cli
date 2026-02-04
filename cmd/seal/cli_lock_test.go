package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"seal/internal/seal"
	"seal/internal/testutil"
	"seal/internal/timeauth"
)

// Test helper - avoid import cycle
func newTestDrandAuthority(currentRound uint64) *timeauth.DrandAuthority {
	fakeHTTP := &testutil.FakeHTTPDoer{
		Responses: map[string]*http.Response{
			"/info":          testutil.MakeDrandInfoResponse(),
			"/public/latest": testutil.MakeDrandPublicResponse(currentRound),
		},
	}
	return timeauth.NewDrandAuthorityWithDeps(fakeHTTP, &testutil.FakeTimelockBox{})
}

func TestLockCommand_OutputContract_Success(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
	tmpHome, cleanup := testutil.SetupTestEnv(t)
	defer cleanup()
	
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
	if !testutil.IsUUID(stdoutTrimmed) {
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
	binPath := testutil.BuildSealBinary(t)

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
	binPath := testutil.BuildSealBinary(t)
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
	if !testutil.IsUUID(stdoutTrimmed) {
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

func TestLockCommand_Shred_Success(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
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
	if !testutil.IsUUID(stdoutTrimmed) {
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
	binPath := testutil.BuildSealBinary(t)
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
	if !testutil.IsUUID(stdoutTrimmed) {
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
	binPath := testutil.BuildSealBinary(t)
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
	binPath := testutil.BuildSealBinary(t)
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

func TestLockCommand_ClearClipboard_Success(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
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
	if !testutil.IsUUID(stdoutTrimmed) {
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
	binPath := testutil.BuildSealBinary(t)
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
	binPath := testutil.BuildSealBinary(t)
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
	binPath := testutil.BuildSealBinary(t)
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
	if !testutil.IsUUID(stdoutTrimmed) {
		t.Errorf("stdout should contain UUID even on clipboard clear failure, got: %q", stdoutStr)
	}

	// Stderr should contain the mandatory warning
	stderrStr := stderr.String()
	expectedWarning := "warning: clipboard clearing is best-effort; the OS or other apps may retain copies"
	if !strings.Contains(stderrStr, expectedWarning) {
		t.Errorf("stderr should contain mandatory warning, got: %q", stderrStr)
	}
}

func TestLockCommand_DefaultsToDrandAuthority(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
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
		t.Fatalf("seal lock failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}

	// Get the item ID from stdout
	itemID := strings.TrimSpace(stdout.String())

	// Read metadata to verify drand authority was used
	var baseDir string
	baseDir = filepath.Join(tmpHome, "Library", "Application Support", "seal")

	metaPath := filepath.Join(baseDir, itemID, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta seal.SealedItem
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	// Verify drand authority was used
	if meta.TimeAuthority != "drand" {
		t.Errorf("expected time_authority 'drand', got %s", meta.TimeAuthority)
	}

	// Verify key_ref is valid drand reference
	var drandRef timeauth.DrandKeyReference
	if err := json.Unmarshal([]byte(meta.KeyRef), &drandRef); err != nil {
		t.Fatalf("key_ref should be valid DrandKeyReference JSON: %v", err)
	}

	if drandRef.Network != "quicknet" {
		t.Errorf("expected network 'quicknet', got %s", drandRef.Network)
	}

	// Verify tlock-encrypted DEK exists
	if meta.DEKTlockB64 == "" {
		t.Error("dek_tlock_b64 should not be empty for drand authority")
	}
}
