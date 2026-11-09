package collect

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// SudoExecTimeout caps the runtime of each `sudo -l -U <user>` probe.
const SudoExecTimeout = 3 * time.Second

// OSCollector emits every edge that comes from the host itself:
//
//   - the SSHComputer node identifying the machine
//   - IsRoot for the UID=0 passwd entry
//   - CanSudo for every user with an unrestricted sudoers grant
//   - one SSHUser node + CanImpersonate edge for every user
//     referenced by any collector during the run
//
// Its emission entry-point is Finalize (not Collect), so OSCollector
// does NOT satisfy the Collector interface. That's intentional: the
// referenced-users pass must run after every domain collector has
// deposited its ReferenceUser marks, and giving OSCollector a different
// method name lets the compiler catch any attempt to add
// &OSCollector{} to the domain-collector slice.
type OSCollector struct{}

// Finalize writes the host node, the privileged-user edges (IsRoot +
// CanSudo), and the deferred SSHUser nodes + CanImpersonate edges.
// Never returns an error today; per-user probe failures log and skip.
func (c *OSCollector) Finalize(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	// emit computer node
	b.AddNode([]string{"SSHComputer"}, h.ComputerID(), map[string]any{
		"name": h.FQDN,
		"FQDN": h.FQDN,
	})

	// emit privileged users
	emitSudoers(ctx, h, b)
	for _, u := range h.Users {
		if u.UID == "0" {
			b.AddEdge("IsRoot",
				opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
				opengraph.ByID("SSHComputer", h.ComputerID()),
				nil)
		}
	}

	// emit users with attack path edges
	for uid := range h.referencedUsers {
		u, ok := h.Users[uid]
		if !ok {
			// ReferenceUser's contract requires uid to be in h.Users;
			// this branch means a caller broke it. Log and skip so
			// we don't nil-deref u.UserName below.
			slog.Error("Finalize: referenced uid missing from h.Users", "uid", uid)
			continue
		}
		id := h.ReferenceUser(uid)
		b.AddNode([]string{"SSHUser"}, id, map[string]any{
			"name": fmt.Sprintf("%s@%s", u.UserName, h.FQDN),
		})
		b.AddEdge("CanImpersonate",
			opengraph.ByID("SSHComputer", h.ComputerID()),
			opengraph.ByID("SSHUser", id),
			nil)
	}
	return nil
}

// emitSudoers emits CanSudo edges for every user in h.Users whose sudo
// policy contains an unrestricted (ALL) ALL grant.
//
// Two paths produce the same edge shape:
//
//  1. Embedded lssudo: one subprocess, parses /etc/sudoers directly, covers
//     every user in /etc/passwd. On success its result set bounds the set
//     of "local" users.
//  2. Fallback `sudo -S -n -l -U <user>`: one subprocess per user, runs
//     only for users lssudo didn't cover (directory users via SSSD/LDAP,
//     or every user if lssudo itself failed).
//
// The classifier that turns a sudoers rendering into (matched,
// passwordRequired) is shared so both paths produce byte-identical edges
// for byte-identical policies.
func emitSudoers(ctx context.Context, h *Host, b *opengraph.GraphBuilder) {
	covered := make(map[string]struct{})
	if entries, err := runLssudo(ctx); err != nil {
		slog.Warn("lssudo probe failed, falling back to per-user sudo for every user", "err", err)
	} else {
		for _, u := range h.Users {
			if sudoerSkip(u) {
				covered[u.UserName] = struct{}{}
				continue
			}
			entry, ok := entries[u.UserName]
			if !ok {
				continue
			}
			covered[u.UserName] = struct{}{}
			blob := strings.Join(entry.Commands, "\n")
			if matched, passwordRequired := classifySudoBlob(blob); matched {
				emitCanSudo(h, u, blob, passwordRequired, b)
			}
		}
	}

	for _, u := range h.Users {
		if _, ok := covered[u.UserName]; ok {
			continue
		}
		if sudoerSkip(u) {
			continue
		}
		emitSudoerViaSudo(ctx, h, u, b)
	}
}

// sudoerSkip returns true for users that should never produce a CanSudo
// edge: UID 0 (already covered by IsRoot) and synthesized "unknown:"
// entries for abandoned home dirs.
func sudoerSkip(u *User) bool {
	if u.UID == "0" {
		slog.Debug("sudoer: user is root, skipping", "userName", u.UserName)
		return true
	}
	if strings.HasPrefix(u.UserName, "unknown:") {
		slog.Debug("sudoer: synthesized user, skipping", "userName", u.UserName)
		return true
	}
	return false
}

// emitSudoerViaSudo runs `sudo -S -n -l -U <user>` and classifies its
// output. Used only for users the embedded lssudo didn't cover (directory
// users) or when lssudo itself failed and we fell back entirely.
func emitSudoerViaSudo(ctx context.Context, h *Host, u *User, b *opengraph.GraphBuilder) {
	cctx, cancel := context.WithTimeout(ctx, SudoExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "sudo", "-S", "-n", "-l", "-U", u.UserName)
	stdOut, err := cmd.Output()
	if err != nil {
		slog.Error("'sudo -S -n -l -U' could not be executed", "userName", u.UserName, "err", err)
		return
	}

	if !strings.Contains(string(stdOut), "may run the following commands on") {
		return
	}
	commands := regexp.MustCompile(`(?s).* may run the following commands on \S+:`).ReplaceAllString(string(stdOut), "")
	commands = regexp.MustCompile(`(?m)^\s+|^\s+$`).ReplaceAllString(commands, "")
	commands = strings.TrimSpace(commands)

	matched, passwordRequired := classifySudoBlob(commands)
	if !matched {
		return
	}
	emitCanSudo(h, u, commands, passwordRequired, b)
}

// emitCanSudo is the single CanSudo edge writer used by both lookup paths.
func emitCanSudo(h *Host, u *User, commands string, passwordRequired bool, b *opengraph.GraphBuilder) {
	b.AddEdge("CanSudo",
		opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
		opengraph.ByID("SSHComputer", h.ComputerID()),
		map[string]any{
			"PasswordRequired": passwordRequired,
			"Commands":         commands,
		})
}
