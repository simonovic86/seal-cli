package main

import (
	"flag"
	"fmt"
	"os"

	"seal/internal/seal"
)

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

	// Print mandatory warning if shredding
	if *shred {
		fmt.Fprintln(os.Stderr, "warning: file shredding on modern filesystems is best-effort only. backups, snapshots, wear leveling, and caches may retain data.")
	}

	// Print mandatory warning if clearing clipboard
	if *clearClip {
		fmt.Fprintln(os.Stderr, "warning: clipboard clearing is best-effort; the OS or other apps may retain copies")
	}

	// Execute lock operation
	result, err := seal.Lock(seal.LockRequest{
		InputPath:      inputPath,
		UnlockTime:     *until,
		Shred:          *shred,
		ClearClipboard: *clearClip,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Print any warnings from shredding or clipboard clearing
	for _, warning := range result.Warnings {
		fmt.Fprintln(os.Stderr, warning)
	}

	fmt.Println(result.ID)
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

	result, err := seal.GetStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Print status output
	output := seal.FormatStatusOutput(result.Items)
	fmt.Print(output)

	// Exit with error if any materialization failed
	if result.MaterializationFailed {
		fmt.Fprintf(os.Stderr, "error: materialization failed: %v\n", result.FirstError)
		os.Exit(1)
	}

	os.Exit(0)
}
