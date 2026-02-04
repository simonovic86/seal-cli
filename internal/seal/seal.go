package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
	"seal/internal/timeauth"
)

// ParseUnlockTime parses and validates an unlock timestamp.
// Accepts only RFC3339 format.
// Rejects past timestamps.
// Returns time normalized to UTC.
func ParseUnlockTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time format, expected RFC3339")
	}

	t = t.UTC()
	now := time.Now().UTC()

	if !t.After(now) {
		return time.Time{}, fmt.Errorf("unlock time must be in the future")
	}

	return t, nil
}

// ReadInput reads input from either a file path or stdin.
// Enforces maximum size limit.
// Returns data, source type, and error.
func ReadInput(path string) ([]byte, InputSource, error) {
	stdinStat, err := os.Stdin.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("cannot stat stdin: %w", err)
	}

	stdinHasData := (stdinStat.Mode() & os.ModeCharDevice) == 0

	// Case: both file path and stdin
	if path != "" && stdinHasData {
		return nil, 0, errors.New("cannot read from both file and stdin")
	}

	// Case: neither file path nor stdin
	if path == "" && !stdinHasData {
		return nil, 0, errors.New("no input provided (use file path or pipe to stdin)")
	}

	var data []byte
	var source InputSource

	if path != "" {
		// Read from file
		source = InputSourceFile
		file, err := os.Open(path)
		if err != nil {
			return nil, 0, fmt.Errorf("cannot open file: %w", err)
		}
		defer file.Close()

		// Check file size
		fileInfo, err := file.Stat()
		if err != nil {
			return nil, 0, fmt.Errorf("cannot stat file: %w", err)
		}

		if fileInfo.Size() > MaxInputSize {
			return nil, 0, fmt.Errorf("input exceeds maximum size of %d bytes", MaxInputSize)
		}

		if fileInfo.Size() == 0 {
			return nil, 0, errors.New("input is empty")
		}

		data, err = io.ReadAll(io.LimitReader(file, MaxInputSize+1))
		if err != nil {
			return nil, 0, fmt.Errorf("cannot read file: %w", err)
		}
	} else {
		// Read from stdin
		source = InputSourceStdin
		data, err = io.ReadAll(io.LimitReader(os.Stdin, MaxInputSize+1))
		if err != nil {
			return nil, 0, fmt.Errorf("cannot read stdin: %w", err)
		}

		if len(data) == 0 {
			return nil, 0, errors.New("input is empty")
		}

		if len(data) > MaxInputSize {
			return nil, 0, fmt.Errorf("input exceeds maximum size of %d bytes", MaxInputSize)
		}
	}

	return data, source, nil
}

// EncryptPayload encrypts plaintext using AES-256-GCM with a fresh DEK.
// Returns ciphertext, nonce (base64), and the unwrapped DEK.
// The DEK must be wrapped before storage.
func EncryptPayload(plaintext []byte) (ciphertext []byte, nonceB64 string, dek []byte, err error) {
	// Generate random 32-byte DEK for AES-256
	dek = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, "", nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	// Encode nonce as base64 for storage
	nonceB64 = base64.StdEncoding.EncodeToString(nonce)

	return ciphertext, nonceB64, dek, nil
}

// ShredFile performs best-effort file shredding.
// Overwrites the file with zeroes, syncs, and removes it.
// Returns a slice of warnings encountered (does not fail on errors).
func ShredFile(path string) []string {
	var warnings []string

	// Open file for writing
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("warning: failed to open file for shredding: %v", err))
		return warnings
	}
	defer file.Close()

	// Get file size
	info, err := file.Stat()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("warning: failed to stat file for shredding: %v", err))
		return warnings
	}

	size := info.Size()

	// Overwrite with zeroes (single pass)
	zeroes := make([]byte, 4096) // Use 4KB buffer for efficiency
	var written int64
	for written < size {
		toWrite := int64(len(zeroes))
		if written+toWrite > size {
			toWrite = size - written
		}

		n, err := file.Write(zeroes[:toWrite])
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("warning: failed to overwrite file during shredding: %v", err))
			return warnings
		}
		written += int64(n)
	}

	// Sync to disk
	if err := file.Sync(); err != nil {
		warnings = append(warnings, fmt.Sprintf("warning: failed to sync file during shredding: %v", err))
	}

	file.Close()

	// Remove file
	if err := os.Remove(path); err != nil {
		warnings = append(warnings, fmt.Sprintf("warning: failed to remove file after shredding: %v", err))
		return warnings
	}

	return warnings
}

// ClearClipboard performs best-effort clipboard clearing.
// Overwrites the system clipboard with an empty string.
// Returns a slice of warnings encountered (does not fail on errors).
func ClearClipboard() []string {
	var warnings []string

	// On macOS, use pbcopy
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("pbcopy")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("warning: failed to access clipboard: %v", err))
			return warnings
		}

		if err := cmd.Start(); err != nil {
			warnings = append(warnings, fmt.Sprintf("warning: failed to start clipboard clear: %v", err))
			return warnings
		}

		// Write empty string to clipboard
		if _, err := stdin.Write([]byte("")); err != nil {
			warnings = append(warnings, fmt.Sprintf("warning: failed to write to clipboard: %v", err))
			stdin.Close()
			cmd.Wait()
			return warnings
		}

		stdin.Close()

		if err := cmd.Wait(); err != nil {
			warnings = append(warnings, fmt.Sprintf("warning: clipboard clear command failed: %v", err))
			return warnings
		}
	} else {
		// On other platforms, we don't attempt to clear
		warnings = append(warnings, "warning: clipboard clearing not implemented for this platform")
	}

	return warnings
}

// CreateSealedItem creates a new sealed item on disk.
// Encrypts the payload using AES-256-GCM with a fresh DEK.
// Uses the provided time authority to generate a key reference.
// Returns the item ID and error.
func CreateSealedItem(unlockTime time.Time, inputType InputSource, originalPath string, plaintext []byte, authority timeauth.TimeAuthority) (string, error) {
	baseDir, err := GetSealBaseDir()
	if err != nil {
		return "", err
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create seal directory: %w", err)
	}

	// Encrypt payload (returns DEK for wrapping)
	ciphertext, nonceB64, dek, err := EncryptPayload(plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}
	defer func() {
		// Zero out DEK from memory after use
		for i := range dek {
			dek[i] = 0
		}
	}()

	// Lock with time authority to get key reference
	keyRef, err := authority.Lock(unlockTime)
	if err != nil {
		return "", fmt.Errorf("time authority lock failed: %w", err)
	}

	// Generate UUID for this sealed item
	id := uuid.New().String()
	itemDir := filepath.Join(baseDir, id)

	// Create item directory
	if err := os.Mkdir(itemDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create item directory: %w", err)
	}

	// Create metadata
	meta := SealedItem{
		ID:            id,
		State:         "sealed",
		UnlockTime:    unlockTime.UTC(),
		InputType:     inputType.String(),
		OriginalPath:  originalPath,
		TimeAuthority: authority.Name(),
		CreatedAt:     time.Now().UTC(),
		Algorithm:     "aes-256-gcm",
		Nonce:         nonceB64,
		KeyRef:        string(keyRef),
	}

	// For drand authority, use tlock to time-lock the DEK
	if drandAuth, ok := authority.(*timeauth.DrandAuthority); ok {
		var drandRef timeauth.DrandKeyReference
		if err := json.Unmarshal([]byte(keyRef), &drandRef); err != nil {
			return "", fmt.Errorf("failed to parse drand key reference: %w", err)
		}

		// Time-lock encrypt the DEK to the target round
		tlockB64, err := drandAuth.Timelock.Encrypt(dek, drandRef.TargetRound)
		if err != nil {
			return "", err
		}

		// Store tlock-encrypted DEK in metadata (base64 encoded)
		meta.DEKTlockB64 = tlockB64
	}

	// Write metadata
	metaPath := filepath.Join(itemDir, "meta.json")
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot marshal metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, metaJSON, 0600); err != nil {
		return "", fmt.Errorf("cannot write metadata: %w", err)
	}

	// Write encrypted payload (ciphertext only, nonce is in metadata)
	payloadPath := filepath.Join(itemDir, "payload.bin")
	if err := os.WriteFile(payloadPath, ciphertext, 0600); err != nil {
		return "", fmt.Errorf("cannot write payload: %w", err)
	}

	return id, nil
}

// LockRequest contains parameters for locking content.
type LockRequest struct {
	InputPath      string
	UnlockTime     string
	Shred          bool
	ClearClipboard bool
}

// LockResult contains the result of a lock operation.
type LockResult struct {
	ID       string
	Warnings []string
}

// Lock encrypts and seals content until a future time.
func Lock(req LockRequest) (LockResult, error) {
	// Parse unlock time
	unlockTime, err := ParseUnlockTime(req.UnlockTime)
	if err != nil {
		return LockResult{}, err
	}

	// Read input data
	inputData, inputSrc, err := ReadInput(req.InputPath)
	if err != nil {
		return LockResult{}, err
	}

	var warnings []string

	// Create time authority (default: drand quicknet)
	authority := timeauth.NewDefaultDrandAuthority()

	// Create sealed item with encrypted payload
	id, err := CreateSealedItem(unlockTime, inputSrc, req.InputPath, inputData, authority)
	if err != nil {
		return LockResult{}, err
	}

	// Shred original file if requested (best-effort, after successful sealing)
	if req.Shred && req.InputPath != "" {
		warnings = append(warnings, ShredFile(req.InputPath)...)
	}

	// Clear clipboard if requested (best-effort, after successful sealing)
	if req.ClearClipboard && req.InputPath == "" {
		warnings = append(warnings, ClearClipboard()...)
	}

	return LockResult{
		ID:       id,
		Warnings: warnings,
	}, nil
}
