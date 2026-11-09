package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LssudoExecTimeout caps the runtime of the embedded lssudo probe.
// lssudo is non-interactive and should complete in milliseconds even on
// large passwd files; the timeout is a defense against hangs.
const LssudoExecTimeout = 10 * time.Second

// lssudoEntry mirrors one JSONL record from `lssudo`.
type lssudoEntry struct {
	Username string   `json:"username"`
	Commands []string `json:"commands"`
}

// runLssudo extracts the embedded lssudo binary, executes it, and parses
// its JSONL output into a map keyed by username. The binary runs as the
// current process's uid: lssudo needs read access to /etc/sudoers, which
// in practice means golinhound must already be running as root.
//
// The returned map contains one entry per local user in /etc/passwd,
// including users with no sudo rules (Commands will be empty). Callers
// use the key set as the "local users covered" marker so they can fall
// back to `sudo -l -U` only for directory users not present here.
//
// On any error — missing embed, extraction failure, non-zero exit,
// malformed JSON — returns (nil, err) so callers can fall back to the
// pre-lssudo code path for every user.
func runLssudo(ctx context.Context) (map[string]lssudoEntry, error) {
	if len(lssudoBinary) == 0 {
		return nil, fmt.Errorf("lssudo binary not embedded for this architecture")
	}

	tmp, err := os.CreateTemp("", "lssudo-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(lssudoBinary); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing lssudo binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing lssudo binary: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o700); err != nil {
		return nil, fmt.Errorf("chmod lssudo binary: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, LssudoExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, tmpPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("lssudo execution failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	entries := make(map[string]lssudoEntry)
	for _, line := range bytes.Split(stdout.Bytes(), []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e lssudoEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("parsing lssudo JSONL line %q: %w", string(line), err)
		}
		entries[e.Username] = e
	}
	return entries, nil
}

// classifySudoBlob returns (matched, passwordRequired) for a sudoers
// policy rendering — either the stdout of `sudo -l -U` or a joined
// lssudo `commands` slice. It matches only unrestricted (ALL) grants;
// narrower per-command grants return matched=false.
//
// The substring patterns are shared between the lssudo and sudo paths
// so both produce the same edge for the same policy.
func classifySudoBlob(blob string) (matched, passwordRequired bool) {
	switch {
	case strings.Contains(blob, "(ALL : ALL) NOPASSWD: ALL"),
		strings.Contains(blob, "(ALL) NOPASSWD: ALL"):
		return true, false
	case strings.Contains(blob, "(ALL : ALL) ALL"),
		strings.Contains(blob, "(ALL) ALL"):
		return true, true
	default:
		return false, false
	}
}
