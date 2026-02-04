package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"seal/internal/testutil"
)

func TestStatusCommand_BeforeUnlock_ReportsSealed(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
	tmpHome := t.TempDir()

	// Create a sealed item with far-future unlock time
	unlockTime := time.Now().UTC().Add(365 * 24 * time.Hour) // 1 year from now
	lockCmd := exec.Command(binPath, "lock", "--until", unlockTime.Format(time.RFC3339))
	lockCmd.Stdin = strings.NewReader("test data")
	lockCmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var lockStdout bytes.Buffer
	lockCmd.Stdout = &lockStdout
	if err := lockCmd.Run(); err != nil {
		t.Fatalf("seal lock failed: %v", err)
	}

	itemID := strings.TrimSpace(lockStdout.String())

	// Run seal status immediately
	statusCmd := exec.Command(binPath, "status")
	statusCmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var statusStdout bytes.Buffer
	statusCmd.Stdout = &statusStdout
	if err := statusCmd.Run(); err != nil {
		t.Fatalf("seal status failed: %v", err)
	}

	output := statusStdout.String()

	// Verify output contains the item ID
	if !strings.Contains(output, itemID) {
		t.Errorf("status output should contain item ID, got: %s", output)
	}

	if !strings.Contains(output, "state: sealed") {
		t.Errorf("status output should show 'state: sealed', got: %s", output)
	}

	if strings.Contains(output, "state: unlocked") {
		t.Errorf("status output should not show 'state: unlocked' for future unlock time, got: %s", output)
	}
}

func TestStatusCommand_AfterUnlock_ReportsUnlocked(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
	tmpHome := t.TempDir()

	// Create a sealed item with near-future unlock time (will unlock quickly in test mode)
	// Use a time 5 seconds in the future - drand rounds every 3 seconds, so this will be
	// unlockable after 1-2 rounds
	unlockTime := time.Now().UTC().Add(5 * time.Second)
	lockCmd := exec.Command(binPath, "lock", "--until", unlockTime.Format(time.RFC3339))
	lockCmd.Stdin = strings.NewReader("test data for unlock")
	lockCmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var lockStdout bytes.Buffer
	lockCmd.Stdout = &lockStdout
	if err := lockCmd.Run(); err != nil {
		t.Fatalf("seal lock failed: %v", err)
	}

	itemID := strings.TrimSpace(lockStdout.String())
	
	// Sleep to ensure the unlock time has passed (wait for drand rounds to catch up)
	time.Sleep(6 * time.Second)

	// Run seal status - should trigger materialization
	statusCmd := exec.Command(binPath, "status")
	statusCmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var statusStdout bytes.Buffer
	statusCmd.Stdout = &statusStdout
	if err := statusCmd.Run(); err != nil {
		t.Fatalf("seal status failed: %v", err)
	}

	output := statusStdout.String()

	// Verify output shows unlocked state
	if !strings.Contains(output, itemID) {
		t.Errorf("status output should contain item ID, got: %s", output)
	}

	if !strings.Contains(output, "state: unlocked") {
		t.Errorf("status output should show 'state: unlocked', got: %s", output)
	}

	// Verify unsealed file exists
	var baseDir string
	if runtime.GOOS == "darwin" {
		baseDir = filepath.Join(tmpHome, "Library", "Application Support", "seal")
	} else {
		baseDir = filepath.Join(tmpHome, ".local", "share", "seal")
	}

	unsealedPath := filepath.Join(baseDir, itemID, "unsealed")
	if _, err := os.Stat(unsealedPath); os.IsNotExist(err) {
		t.Error("unsealed file should exist after materialization")
	}

	// Run status again - should be idempotent (still show unlocked, no errors)
	statusCmd2 := exec.Command(binPath, "status")
	statusCmd2.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var statusStdout2 bytes.Buffer
	statusCmd2.Stdout = &statusStdout2
	if err := statusCmd2.Run(); err != nil {
		t.Fatalf("second seal status failed: %v", err)
	}

	output2 := statusStdout2.String()
	if !strings.Contains(output2, "state: unlocked") {
		t.Errorf("second status should still show 'state: unlocked', got: %s", output2)
	}
}

func TestStatusCommand_NoSpecialMessageOnUnlock(t *testing.T) {
	binPath := testutil.BuildSealBinary(t)
	tmpHome := t.TempDir()

	// Create a sealed item with near-future unlock time
	unlockTime := time.Now().UTC().Add(5 * time.Second)
	lockCmd := exec.Command(binPath, "lock", "--until", unlockTime.Format(time.RFC3339))
	lockCmd.Stdin = strings.NewReader("test data")
	lockCmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var lockStdout bytes.Buffer
	lockCmd.Stdout = &lockStdout
	if err := lockCmd.Run(); err != nil {
		t.Fatalf("seal lock failed: %v", err)
	}

	itemID := strings.TrimSpace(lockStdout.String())
	
	// Sleep to ensure unlock
	time.Sleep(6 * time.Second)

	// Run seal status
	statusCmd := exec.Command(binPath, "status")
	statusCmd.Env = append(os.Environ(), "HOME="+tmpHome, "XDG_DATA_HOME=")

	var statusStdout bytes.Buffer
	statusCmd.Stdout = &statusStdout
	if err := statusCmd.Run(); err != nil {
		t.Fatalf("seal status failed: %v", err)
	}

	output := statusStdout.String()

	// Verify item ID is present
	if !strings.Contains(output, itemID) {
		t.Errorf("status output should contain item ID, got: %s", output)
	}

	// Verify no celebration or special messages
	// Seal is deterministic and factual - no "unlocked!", "ready!", "available", etc.
	forbiddenPhrases := []string{
		"unlocked!",
		"ready",
		"available",
		"success",
		"completed",
		"now accessible",
	}

	lowerOutput := strings.ToLower(output)
	for _, phrase := range forbiddenPhrases {
		if strings.Contains(lowerOutput, phrase) {
			t.Errorf("output should not contain special unlock message with phrase '%s', got: %s", phrase, output)
		}
	}
}
