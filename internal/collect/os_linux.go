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
	for _, u := range h.Users {
		if u.UID == "0" {
			b.AddEdge("IsRoot",
				opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
				opengraph.ByID("SSHComputer", h.ComputerID()),
				nil)
		}
		emitSudoer(ctx, h, u, b)
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

// emitSudoer queries `sudo -l -U <user>` and adds a CanSudo edge if the
// user holds an unrestricted (ALL) ALL or (ALL : ALL) ALL grant. Narrower
// per-command grants are intentionally skipped.
func emitSudoer(ctx context.Context, h *Host, u *User, b *opengraph.GraphBuilder) {
	if u.UID == "0" {
		slog.Debug("emitSudoer: user is root, skipping", "userName", u.UserName)
		return
	}
	// handle abandoned home dirs
	if strings.HasPrefix(u.UserName, "unknown:") {
		slog.Debug("emitSudoer: synthesized user, skipping", "userName", u.UserName)
		return
	}

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

	var passwordRequired bool
	switch {
	case strings.Contains(commands, "(ALL : ALL) NOPASSWD: ALL"),
		strings.Contains(commands, "(ALL) NOPASSWD: ALL"):
		passwordRequired = false
	case strings.Contains(commands, "(ALL : ALL) ALL"),
		strings.Contains(commands, "(ALL) ALL"):
		passwordRequired = true
	default:
		return
	}

	b.AddEdge("CanSudo",
		opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
		opengraph.ByID("SSHComputer", h.ComputerID()),
		map[string]any{
			"PasswordRequired": passwordRequired,
			"Commands":         commands,
		})
}
