package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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

// SealedItem represents metadata for a sealed item.
type SealedItem struct {
	ID              string    `json:"id"`
	UnlockTime      time.Time `json:"unlock_time"`
	InputType       string    `json:"input_type"`
	OriginalPath    string    `json:"original_path,omitempty"`
	TimeAuthority   string    `json:"time_authority"`
	CreatedAt       time.Time `json:"created_at"`
}

const usageText = `seal - irreversible time-locked commitment primitive

Usage:
  seal lock <path> --until <time>
  seal lock --until <time>          (reads from stdin)
  seal status

Options:
  --until <time>    RFC3339 timestamp for unlock time

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
// Returns the item ID and error.
func createSealedItem(unlockTime time.Time, inputType inputSource, originalPath string, payload []byte) (string, error) {
	baseDir, err := getSealBaseDir()
	if err != nil {
		return "", err
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create seal directory: %w", err)
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
		UnlockTime:    unlockTime.UTC(),
		InputType:     inputType.String(),
		OriginalPath:  originalPath,
		TimeAuthority: "placeholder", // TODO: implement time authority
		CreatedAt:     time.Now().UTC(),
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

	// Write payload (encrypted placeholder for now)
	payloadPath := filepath.Join(itemDir, "payload.bin")
	if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
		return "", fmt.Errorf("cannot write payload: %w", err)
	}

	return id, nil
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

		metaPath := filepath.Join(baseDir, entry.Name(), "meta.json")
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

	lockFlags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: seal lock <path> --until <time>")
		fmt.Fprintln(os.Stderr, "       seal lock --until <time>  (reads from stdin)")
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

	inputData, inputSrc, err := readInput(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Create sealed item (payload is unencrypted placeholder for now)
	id, err := createSealedItem(unlockTime, inputSrc, inputPath, inputData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
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
