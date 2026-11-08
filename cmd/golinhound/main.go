package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/RantaSec/golinhound/internal/collect"
	"github.com/RantaSec/golinhound/internal/opengraph"
)

// installLogger sets the default slog logger to JSON-on-stderr; verbose enables Debug.
func installLogger(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func main() {
	collectCmd := flag.NewFlagSet("collect", flag.ExitOnError)
	collectDuration := collectCmd.Int("wait-for-keys", 0, "Time in minutes to wait for new forwarded SSH keys (0 = no wait)")
	collectExpiredCerts := collectCmd.Bool("include-expired-certs", false, "Also collect SSH certificates whose ValidBefore is in the past")
	collectVerbose := collectCmd.Bool("verbose", false, "Enable verbose output")
	mergeCmd := flag.NewFlagSet("merge", flag.ExitOnError)
	mergeVerbose := mergeCmd.Bool("verbose", false, "Enable verbose output")
	if len(os.Args) < 2 {
		printCommandUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "collect":
		collectCmd.Parse(os.Args[2:])
		installLogger(*collectVerbose)
		result, err := collect.Run(context.Background(), collect.Options{
			WaitForKeysDuration:        *collectDuration,
			CollectExpiredCertificates: *collectExpiredCerts,
		})
		if err != nil {
			slog.Error("collect failed", "err", err)
			os.Exit(1)
		}
		fmt.Println(result)
	case "merge":
		mergeCmd.Parse(os.Args[2:])
		installLogger(*mergeVerbose)
		result, err := opengraph.MergeOpenGraphJSONs(os.Stdin)
		if err != nil {
			slog.Error("merge failed", "err", err)
			os.Exit(1)
		}
		fmt.Println(string(result))
	default:
		printCommandUsage()
		os.Exit(1)
	}
}

// printCommandUsage prints the subcommand usage to stderr
func printCommandUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s <command> [options]

Commands:
 collect    collect attack path data from current computer (requires root privileges)
 merge      read stream of OpenGraph JSON objects from stdin and merge them into one JSON

Use "%s <command> -h" for more information about a command.

Copyright (c) 2026 Lukas Klein
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}
