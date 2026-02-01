package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

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

	unlockTime, err := time.Parse(time.RFC3339, *until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid time format: %v\n", err)
		fmt.Fprintln(os.Stderr, "expected RFC3339 format (e.g., 2026-02-01T15:04:05Z)")
		os.Exit(1)
	}

	now := time.Now()
	if !unlockTime.After(now) {
		fmt.Fprintln(os.Stderr, "error: unlock time must be in the future")
		os.Exit(1)
	}

	var inputPath string
	remaining := lockFlags.Args()

	if len(remaining) > 1 {
		fmt.Fprintln(os.Stderr, "error: too many arguments")
		lockFlags.Usage()
		os.Exit(1)
	}

	if len(remaining) == 1 {
		inputPath = remaining[0]
		if _, err := os.Stat(inputPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error: file does not exist: %s\n", inputPath)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stderr, "error: lock not implemented")
	os.Exit(1)
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

	fmt.Fprintln(os.Stderr, "error: status not implemented")
	os.Exit(1)
}
