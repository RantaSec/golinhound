package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/RantaSec/golinhound/internal/collect"
	"github.com/RantaSec/golinhound/internal/configure"
	"github.com/RantaSec/golinhound/internal/opengraph"
	"golang.org/x/term"
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
	collectVerbose := collectCmd.Bool("verbose", false, "Enable verbose output")
	mergeCmd := flag.NewFlagSet("merge", flag.ExitOnError)
	mergeVerbose := mergeCmd.Bool("verbose", false, "Enable verbose output")
	configureCmd := flag.NewFlagSet("configure", flag.ExitOnError)
	configureURL := configureCmd.String("url", "", "BloodHound base URL (e.g. http://localhost:8080)")
	configureUser := configureCmd.String("user", "", "BloodHound username")
	configureInsecure := configureCmd.Bool("insecure", false, "Skip TLS certificate verification")

	if len(os.Args) < 2 {
		printCommandUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "collect":
		collectCmd.Parse(os.Args[2:])
		installLogger(*collectVerbose)
		result, err := collect.Run(context.Background(), collect.Options{
			WaitForKeysDuration: *collectDuration,
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
	case "configure":
		configureCmd.Parse(os.Args[2:])
		if *configureURL == "" || *configureUser == "" {
			fmt.Fprintln(os.Stderr, "configure: -url and -user are required")
			configureCmd.Usage()
			os.Exit(1)
		}
		if err := runConfigure(*configureURL, *configureUser, *configureInsecure); err != nil {
			fmt.Fprintf(os.Stderr, "configure: %v\n", err)
			os.Exit(1)
		}
	default:
		printCommandUsage()
		os.Exit(1)
	}
}

// runConfigure prompts for a password and uploads the embedded custom node
// icons to BloodHound.
func runConfigure(url, user string, insecure bool) error {
	fmt.Fprintf(os.Stderr, "Password for %s: ", user)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if err := configure.Run(url, user, string(pw), insecure); err != nil {
		return err
	}
	fmt.Println("BloodHound configured: custom node icons uploaded.")
	return nil
}

// printCommandUsage prints the subcommand usage to stderr
func printCommandUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s <command> [options]

Commands:
 collect    collect attack path data from current computer (requires root privileges)
 merge      read stream of OpenGraph JSON objects from stdin and merge them into one JSON
 configure  configure custom node icons in BloodHound

Use "%s <command> -h" for more information about a command.

Copyright (c) 2026 Lukas Klein
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}
