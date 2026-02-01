package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	maxInputSize = 10 * 1024 * 1024 // 10MB
)

type inputSource int

const (
	inputSourceFile inputSource = iota
	inputSourceStdin
)

func (i inputSource) String() string {
	if i == inputSourceFile {
		return "file"
	}
	return "stdin"
}

// KeyReference is an opaque reference to a time-locked encryption key.
type KeyReference string

// TimeAuthority is an external, verifiable source of truth for time-based unlocking.
type TimeAuthority interface {
	// Name returns the identifier for this time authority.
	Name() string

	// Lock creates a time-locked key reference for the given unlock time.
	// Returns an opaque key reference that can later be used to determine unlock eligibility.
	Lock(unlockTime time.Time) (KeyReference, error)

	// CanUnlock determines whether the unlock time has been reached.
	// Returns true if unlocking is permitted, false otherwise.
	CanUnlock(ref KeyReference, now time.Time) (bool, error)
}

// PlaceholderAuthority is a no-op time authority for testing and development.
// It never permits unlocking.
type PlaceholderAuthority struct{}

func (p *PlaceholderAuthority) Name() string {
	return "placeholder"
}

func (p *PlaceholderAuthority) Lock(unlockTime time.Time) (KeyReference, error) {
	// Return a dummy key reference
	return KeyReference("placeholder-key-ref"), nil
}

func (p *PlaceholderAuthority) CanUnlock(ref KeyReference, now time.Time) (bool, error) {
	// Always returns false - no unlocking permitted
	return false, nil
}

// SealedItem represents metadata for a sealed item.
type SealedItem struct {
	ID              string    `json:"id"`
	State           string    `json:"state"`
	UnlockTime      time.Time `json:"unlock_time"`
	InputType       string    `json:"input_type"`
	OriginalPath    string    `json:"original_path,omitempty"`
	TimeAuthority   string    `json:"time_authority"`
	CreatedAt       time.Time `json:"created_at"`
	Algorithm       string    `json:"algorithm"`
	Nonce           string    `json:"nonce"`
	KeyRef          string    `json:"key_ref"`
}

const usageText = `seal - irreversible time-locked commitment primitive

Usage:
  seal lock <path> --until <time> [--shred]
  seal lock --until <time> [--clear-clipboard]  (reads from stdin)
  seal status

Options:
  --until <time>         RFC3339 timestamp for unlock time
  --shred                best-effort file shredding (file input only)
  --clear-clipboard      best-effort clipboard clearing (stdin only)

seal lock encrypts data until a specified future time.
seal status shows information about sealed commitments.

No undo. No early unlock. No recovery.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usageText)
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "lock":
		handleLock(os.Args[2:])
	case "status":
		handleStatus(os.Args[2:])
	case "help", "--help", "-h":
		fmt.Println(usageText)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		fmt.Fprintln(os.Stderr, usageText)
		os.Exit(1)
	}
}

// parseUnlockTime parses and validates an unlock timestamp.
// Accepts only RFC3339 format.
// Rejects past timestamps.
// Returns time normalized to UTC.
func parseUnlockTime(s string) (time.Time, error) {
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

// readInput reads input from either a file path or stdin.
// Enforces maximum size limit.
// Returns data, source type, and error.
func readInput(path string) ([]byte, inputSource, error) {
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
	var source inputSource

	if path != "" {
		// Read from file
		source = inputSourceFile
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

		if fileInfo.Size() > maxInputSize {
			return nil, 0, fmt.Errorf("input exceeds maximum size of %d bytes", maxInputSize)
		}

		if fileInfo.Size() == 0 {
			return nil, 0, errors.New("input is empty")
		}

		data, err = io.ReadAll(io.LimitReader(file, maxInputSize+1))
		if err != nil {
			return nil, 0, fmt.Errorf("cannot read file: %w", err)
		}
	} else {
		// Read from stdin
		source = inputSourceStdin
		data, err = io.ReadAll(io.LimitReader(os.Stdin, maxInputSize+1))
		if err != nil {
			return nil, 0, fmt.Errorf("cannot read stdin: %w", err)
		}

		if len(data) == 0 {
			return nil, 0, errors.New("input is empty")
		}

		if len(data) > maxInputSize {
			return nil, 0, fmt.Errorf("input exceeds maximum size of %d bytes", maxInputSize)
		}
	}

	return data, source, nil
}

// encryptPayload encrypts plaintext using AES-256-GCM.
// Returns ciphertext and nonce (base64 encoded).
// The symmetric key is generated and discarded (not stored anywhere).
// Payload format: only ciphertext is stored; nonce is stored in metadata.
func encryptPayload(plaintext []byte) (ciphertext []byte, nonceB64 string, err error) {
	// Generate random 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", fmt.Errorf("failed to generate key: %w", err)
	}
	defer func() {
		// Zero out key from memory (best effort)
		for i := range key {
			key[i] = 0
		}
	}()

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	// Encode nonce as base64 for storage
	nonceB64 = base64.StdEncoding.EncodeToString(nonce)

	return ciphertext, nonceB64, nil
}

// shredFile performs best-effort file shredding.
// Overwrites the file with zeroes, syncs, and removes it.
// Returns a slice of warnings encountered (does not fail on errors).
func shredFile(path string) []string {
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

// clearClipboard performs best-effort clipboard clearing.
// Overwrites the system clipboard with an empty string.
// Returns a slice of warnings encountered (does not fail on errors).
func clearClipboard() []string {
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

// getSealBaseDir returns the OS-appropriate base directory for Seal data.
func getSealBaseDir() (string, error) {
	var baseDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot get home directory: %w", err)
		}
		baseDir = filepath.Join(home, "Library", "Application Support", "seal")

	case "windows":
		appData := os.Getenv("AppData")
		if appData == "" {
			return "", errors.New("AppData environment variable not set")
		}
		baseDir = filepath.Join(appData, "seal")

	default: // Linux and other Unix-like systems
		xdgDataHome := os.Getenv("XDG_DATA_HOME")
		if xdgDataHome != "" {
			baseDir = filepath.Join(xdgDataHome, "seal")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("cannot get home directory: %w", err)
			}
			baseDir = filepath.Join(home, ".local", "share", "seal")
		}
	}

	return baseDir, nil
}

// createSealedItem creates a new sealed item on disk.
// Encrypts the payload using AES-256-GCM.
// Uses the provided time authority to generate a key reference.
// Returns the item ID and error.
func createSealedItem(unlockTime time.Time, inputType inputSource, originalPath string, plaintext []byte, authority TimeAuthority) (string, error) {
	baseDir, err := getSealBaseDir()
	if err != nil {
		return "", err
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create seal directory: %w", err)
	}

	// Encrypt payload
	ciphertext, nonceB64, err := encryptPayload(plaintext)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

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

// checkAndTransitionUnlock checks if a sealed item can be unlocked and transitions it.
// This function defines the unlock flow but is currently inert (does not unlock).
// 
// When unlocking is implemented, decrypted data will be written to:
//   <itemDir>/unsealed
// 
// This path must not exist while the item is in "sealed" state.
// Returns the item (potentially with updated state) and any error.
func checkAndTransitionUnlock(item SealedItem, itemDir string) (SealedItem, error) {
	// If already unlocked, do nothing
	if item.State == "unlocked" {
		return item, nil
	}

	// If still sealed, check conditions (currently inert - does not unlock)
	if item.State == "sealed" {
		// TODO: check time authority
		// TODO: decrypt payload
		// TODO: write to <itemDir>/unsealed
		// TODO: update state to "unlocked"
		// For now, do nothing
		return item, nil
	}

	return item, nil
}

// listSealedItems returns all sealed items, sorted by creation time (oldest first).
func listSealedItems() ([]SealedItem, error) {
	baseDir, err := getSealBaseDir()
	if err != nil {
		return nil, err
	}

	// Check if base directory exists
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		return []SealedItem{}, nil // No items yet
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read seal directory: %w", err)
	}

	var items []SealedItem
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		itemDir := filepath.Join(baseDir, entry.Name())
		metaPath := filepath.Join(itemDir, "meta.json")
		metaData, err := os.ReadFile(metaPath)
		if err != nil {
			// Skip invalid items
			continue
		}

		var item SealedItem
		if err := json.Unmarshal(metaData, &item); err != nil {
			// Skip invalid items
			continue
		}

		// Check and potentially transition unlock state (currently inert)
		item, err = checkAndTransitionUnlock(item, itemDir)
		if err != nil {
			// Skip items that fail unlock check
			continue
		}

		items = append(items, item)
	}

	// Sort by creation time (oldest first)
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})

	return items, nil
}

func handleLock(args []string) {
	lockFlags := flag.NewFlagSet("lock", flag.ExitOnError)
	until := lockFlags.String("until", "", "RFC3339 timestamp for unlock time")
	shred := lockFlags.Bool("shred", false, "best-effort file shredding (file input only)")
	clearClip := lockFlags.Bool("clear-clipboard", false, "best-effort clipboard clearing (stdin only)")

	lockFlags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: seal lock <path> --until <time> [--shred]")
		fmt.Fprintln(os.Stderr, "       seal lock --until <time> [--clear-clipboard]  (reads from stdin)")
		lockFlags.PrintDefaults()
	}

	lockFlags.Parse(args)

	if *until == "" {
		fmt.Fprintln(os.Stderr, "error: --until is required")
		lockFlags.Usage()
		os.Exit(1)
	}

	unlockTime, err := parseUnlockTime(*until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	remaining := lockFlags.Args()

	if len(remaining) > 1 {
		fmt.Fprintln(os.Stderr, "error: too many arguments")
		lockFlags.Usage()
		os.Exit(1)
	}

	var inputPath string
	if len(remaining) == 1 {
		inputPath = remaining[0]
	}

	// Validate --shred usage
	if *shred && inputPath == "" {
		fmt.Fprintln(os.Stderr, "error: --shred can only be used with file input")
		os.Exit(1)
	}

	// Validate --clear-clipboard usage
	if *clearClip && inputPath != "" {
		fmt.Fprintln(os.Stderr, "error: --clear-clipboard can only be used with stdin input")
		os.Exit(1)
	}

	inputData, inputSrc, err := readInput(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Print mandatory warning if shredding
	if *shred {
		fmt.Fprintln(os.Stderr, "warning: file shredding on modern filesystems is best-effort only. backups, snapshots, wear leveling, and caches may retain data.")
	}

	// Print mandatory warning if clearing clipboard
	if *clearClip {
		fmt.Fprintln(os.Stderr, "warning: clipboard clearing is best-effort; the OS or other apps may retain copies")
	}

	// Create time authority
	authority := &PlaceholderAuthority{}

	// Create sealed item with encrypted payload
	id, err := createSealedItem(unlockTime, inputSrc, inputPath, inputData, authority)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Shred original file if requested (best-effort, after successful sealing)
	if *shred && inputPath != "" {
		warnings := shredFile(inputPath)
		for _, warning := range warnings {
			fmt.Fprintln(os.Stderr, warning)
		}
	}

	// Clear clipboard if requested (best-effort, after successful sealing)
	if *clearClip && inputPath == "" {
		warnings := clearClipboard()
		for _, warning := range warnings {
			fmt.Fprintln(os.Stderr, warning)
		}
	}

	fmt.Println(id)
	os.Exit(0)
}

func handleStatus(args []string) {
	statusFlags := flag.NewFlagSet("status", flag.ExitOnError)
	statusFlags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: seal status")
	}

	statusFlags.Parse(args)

	if len(statusFlags.Args()) > 0 {
		fmt.Fprintln(os.Stderr, "error: status takes no arguments")
		statusFlags.Usage()
		os.Exit(1)
	}

	items, err := listSealedItems()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(items) == 0 {
		fmt.Println("no sealed items")
		os.Exit(0)
	}

	for _, item := range items {
		fmt.Printf("%s %s %s\n", item.ID, item.UnlockTime.Format(time.RFC3339), item.InputType)
	}

	os.Exit(0)
}
