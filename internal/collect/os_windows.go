package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"golang.org/x/sys/windows"
)

// LocalAdminsTimeout bounds the `net localgroup` probe.
const LocalAdminsTimeout = 2 * time.Second

// The BUILTIN\Administrators alias SID — the same well-known SID on
// every Windows install regardless of locale.
const builtinAdministratorsSID = "S-1-5-32-544"

// OSCollector emits every edge that comes from the host itself:
//
//   - the SSHComputer node identifying the machine
//   - AdminTo for every h.Users entry in the local Administrators
//     group (see emitAdmins)
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

// Finalize writes the host node, AdminTo edges from Administrators
// group members, and the deferred SSHUser nodes + CanImpersonate
// edges.
func (c *OSCollector) Finalize(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	// emit computer node
	b.AddNode([]string{"SSHComputer"}, h.ComputerID(), map[string]any{
		"name": h.FQDN,
		"FQDN": h.FQDN,
	})

	// emit AdminTo edges for local Administrators group members
	emitAdmins(ctx, h, b)

	// emit users with attack path edges
	for uid := range h.referencedUsers {
		u, ok := h.Users[uid]
		if !ok {
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

// emitAdmins reads the Administrators group's member set via
// `net.exe localgroup` and emits an AdminTo edge for each h.Users
// entry whose UserName appears in that set. Members not in h.Users
// (nested groups, domain accounts without a local profile) are
// silently dropped, mirroring the Linux emitSudoer behavior for
// LDAP-only sudoers.
func emitAdmins(ctx context.Context, h *Host, b *opengraph.GraphBuilder) {
	members, err := readLocalAdminNames(ctx)
	if err != nil {
		slog.Error("emitAdmins: could not enumerate Administrators group", "err", err)
		return
	}
	for _, u := range h.Users {
		if !adminMatch(members, u.UserName) {
			continue
		}
		b.AddEdge("AdminTo",
			opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
			opengraph.ByID("SSHComputer", h.ComputerID()),
			nil)
	}
}

// adminMatch reports whether userName appears in members. The
// members set is built to hold both DOMAIN\name and bare-name
// forms; userName from h.Users is checked in both forms too so a
// mismatch of prefix conventions between `net localgroup` output
// and LookupAccountSid can't hide a real admin.
func adminMatch(members map[string]struct{}, userName string) bool {
	name := strings.ToLower(userName)
	if _, ok := members[name]; ok {
		return true
	}
	if _, bare, ok := strings.Cut(name, `\`); ok {
		if _, ok := members[bare]; ok {
			return true
		}
	}
	return false
}

// readLocalAdminNames returns the Administrators-group member set as
// lower-cased display names ("corp\\alice", "administrator", ...).
// Uses the well-known SID S-1-5-32-544 to look up the localized
// group name and then runs `net.exe localgroup <name>`. Parsing
// anchors on the "---" separator that appears between the header
// and the member rows in every locale.
func readLocalAdminNames(ctx context.Context) (map[string]struct{}, error) {
	sid, err := windows.StringToSid(builtinAdministratorsSID)
	if err != nil {
		return nil, fmt.Errorf("parse Administrators SID: %w", err)
	}
	groupName, _, _, err := sid.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("resolve Administrators localized name: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, LocalAdminsTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "net.exe", "localgroup", groupName)
	out, err := cmd.Output()
	if err != nil {
		// Surface stderr when present so a misconfigured host gives
		// a diagnostic better than "exit status 2".
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("net localgroup %q: %w: %s", groupName, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("net localgroup %q: %w", groupName, err)
	}

	// `net localgroup` output is a series of blank-line-separated
	// paragraphs. The one we want starts with a line of dashes and
	// contains one member per subsequent line. Every other paragraph
	// (header, "Members" label, footer) is localized and can be
	// skipped by the "starts with dashes" test.
	//
	// Each member is inserted twice: once as the raw `net`-printed
	// form, once as the bare account name (the last component after
	// any DOMAIN\ prefix). h.Users can carry either form depending
	// on whether LookupAccountSid returned a domain — the built-in
	// local Administrator is stored as MACHINE\Administrator while
	// `net` prints just Administrator, so matching either form
	// covers every account.
	text := strings.ReplaceAll(string(out), "\r", "")
	members := make(map[string]struct{})
	for _, block := range strings.Split(text, "\n\n") {
		first, rest, ok := strings.Cut(strings.TrimSpace(block), "\n")
		if !ok || strings.Trim(first, "-") != "" {
			continue
		}
		for line := range strings.SplitSeq(rest, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			name := strings.ToLower(line)
			members[name] = struct{}{}
			if _, bare, ok := strings.Cut(name, `\`); ok {
				members[bare] = struct{}{}
			}
		}
		return members, nil
	}
	return nil, errors.New("net localgroup: member block not found")
}
