package collect

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// SessionStartMessageID is the SD_ID128 logind stamp of
	// SD_MESSAGE_SESSION_START journal records.
	SessionStartMessageID = "8d45620c1a4348dbb17410da57c60c66"
	// SessionHistoryDays bounds how far back journalctl scans for user sessions.
	SessionHistoryDays = 7
	// JournalctlTimeout caps the time we spend on searching user sessions in the journal.
	JournalctlTimeout = 30 * time.Second
	// GetentTimeout limits the execution time of `getent passwd <user>`.
	GetentTimeout = 3 * time.Second
	// MaxHomeDirGlobWildcards caps how many `*`s a home-dir glob may
	// contain. Realistic sssd.conf templates use one or two
	// placeholders (%u, %d/%u)
	MaxHomeDirGlobWildcards = 2
)

// User is one local account
type User struct {
	UserName string
	UID      string
	Shell    string
	HomeDir  string
}

// Host is a per-run snapshot of the machine state. referencedUsers
// is the set of UIDs some collector has referenced during the run.
type Host struct {
	uniqueId        string
	FQDN            string
	Users           map[string]*User
	referencedUsers map[string]struct{}
}

// NewHost captures a per-run snapshot of the machine: HMAC'd
// machine-id, FQDN, and the enumerated user set. Root is required
// so /etc/passwd and journalctl reads never fail on permissions.
func NewHost() (*Host, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("this program must run as root")
	}

	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, fmt.Errorf("/etc/machine-id: %w", err)
	}
	machineId := strings.TrimSuffix(string(raw), "\n")
	if len(machineId) != 32 {
		return nil, fmt.Errorf("/etc/machine-id: expected 32 bytes, got %d", len(machineId))
	}
	h := hmac.New(sha256.New, []byte("fLhn74XaBtmouSQkBSRIAm6tbISvrf26"))
	h.Write([]byte(machineId))
	uniqueId := strings.TrimRight(base64.StdEncoding.EncodeToString(h.Sum(nil)), "=")

	fqdn, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}

	users, err := enumerateUsers()
	if err != nil {
		return nil, err
	}

	return &Host{
		uniqueId:        uniqueId,
		FQDN:            fqdn,
		Users:           users,
		referencedUsers: make(map[string]struct{}),
	}, nil
}

// ComputerID returns the HMAC'd machine-id used as the stable
// per-host identifier in the graph.
func (h *Host) ComputerID() string { return h.uniqueId }

// ReferenceUser marks uid for emission and returns its SSHUser id.
// Every caller should be inline in an AddEdge argument list. The
// mark drives OSCollector.Finalize's per-user emission.
func (h *Host) ReferenceUser(uid string) string {
	h.referencedUsers[uid] = struct{}{}
	return uid + "@" + h.uniqueId
}

// fileOwner returns the *User that owns the given file, resolved via
// os.Stat + h.Users lookup. Returns nil (and logs at Debug) when the
// file's owning uid has no matching entry — e.g. userns-remapped uids,
// container-only uids not present in /etc/passwd, or uids the local
// system doesn't know about. Callers treat nil as "skip — can't
// attribute to any local user."
func (h *Host) fileOwner(path string) *User {
	fi, err := os.Stat(path)
	if err != nil {
		slog.Debug("fileOwner: stat failed", "path", path, "err", err)
		return nil
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		slog.Debug("fileOwner: syscall.Stat_t unavailable", "path", path)
		return nil
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	u, ok := h.Users[uid]
	if !ok {
		slog.Debug("fileOwner: uid not in Host.Users", "path", path, "uid", uid)
		return nil
	}
	return u
}

// enumerateUsers reads /etc/passwd into a UID-keyed map, then
// enriches it with SSSD-backed accounts via enrichFromJournal
// (recent logind SESSION_START records -> getent) and
// enrichWithHomeDirs (sssd.conf home-dir globs -> getent). Both
// enrichments fail soft and are no-ops on non-SSSD hosts.
func enumerateUsers() (map[string]*User, error) {
	slog.Debug("enumerateUsers")
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("/etc/passwd: %w", err)
	}
	users := make(map[string]*User)
	for line := range strings.SplitSeq(string(data), "\n") {
		if u, ok := parsePasswdLine(line); ok {
			users[u.UID] = u
		}
	}
	enrichFromJournal(users)
	enrichWithHomeDirs(users)
	return users, nil
}

// parsePasswdLine parses one passwd line into a *User; used for
// both /etc/passwd and `getent passwd` output.
func parsePasswdLine(line string) (*User, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}
	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		return nil, false
	}
	return &User{
		UserName: fields[0],
		UID:      fields[2],
		HomeDir:  fields[5],
		Shell:    fields[6],
	}, true
}

// enrichFromJournal reads recent logind SESSION_START records from
// journald and, for each USER_ID not already in `users`, resolves
// it via `getent passwd`. Every pam_systemd-based login emits such
// a record.
func enrichFromJournal(users map[string]*User) {
	slog.Debug("enrichFromJournal")

	names, err := recentSessionUserNames()
	if err != nil {
		slog.Error("enrichFromJournal: could not read journal", "err", err)
		return
	}

	knownNames := make(map[string]struct{}, len(users))
	for _, u := range users {
		knownNames[u.UserName] = struct{}{}
	}

	for name := range names {
		if _, ok := knownNames[name]; ok {
			continue
		}
		u, ok := getentPasswd(name)
		if !ok {
			continue
		}
		users[u.UID] = u
	}
}

// recentSessionUserNames returns the distinct USER_ID values from
// SESSION_START records in the last SessionHistoryDays.
func recentSessionUserNames() (map[string]struct{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), JournalctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl",
		"MESSAGE_ID="+SessionStartMessageID,
		"-o", "json",
		// --output-fields would reduce the output JSON to just USER_ID,
		// but it only exists since systemd v236 (commit cc25a67e, 2017-10-27)
		//"--output-fields", "USER_ID",
		"--since", fmt.Sprintf("%d days ago", SessionHistoryDays),
		"--no-pager",
	)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("journalctl: %w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("journalctl: %w", err)
	}

	names := make(map[string]struct{})
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var rec struct {
			UserID string `json:"USER_ID"`
		}
		if err := dec.Decode(&rec); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("journalctl json: %w", err)
		}
		names[rec.UserID] = struct{}{}
	}
	return names, nil
}

// getentPasswd runs `getent passwd <name>` and parses the result.
// NSS accepts either a name or a numeric UID. Returns (nil, false)
// on any failure.
func getentPasswd(name string) (*User, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), GetentTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "passwd", name).Output()
	if err != nil {
		// exit code 2: user not found. This is expected on stale accounts.
		// We only output unexpected errors here.
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
			slog.Error("getentPasswd: exit non-zero", "name", name, "err", err)
		}
		return nil, false
	}
	line := string(out)
	u, ok := parsePasswdLine(line)
	if !ok {
		slog.Error("getentPasswd: unparseable passwd line", "name", name, "line", line)
		return nil, false
	}
	return u, true
}

// enrichWithHomeDirs globs sssd.conf home-dir templates for
// matching directories on disk and adds one *User per unclaimed
// hit. `getent passwd <uid>` provides the display name and shell
// for live accounts; directories whose UID isn't resolvable via
// NSS (removed user, abandoned home dir) still get an entry with
// UserName "unknown:<uid>".
func enrichWithHomeDirs(users map[string]*User) {
	slog.Debug("enrichWithHomeDirs")
	claimed := make(map[string]struct{}, len(users))
	for _, u := range users {
		claimed[filepath.Clean(u.HomeDir)] = struct{}{}
	}
	for pattern := range sssdHomeDirGlobs() {
		for _, dir := range localGlobMatches(pattern) {
			cleaned := filepath.Clean(dir)
			if _, ok := claimed[cleaned]; ok {
				continue
			}
			fi, err := os.Stat(dir)
			if err != nil || !fi.IsDir() {
				continue
			}
			stat, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				slog.Debug("enrichWithHomeDirs: syscall.Stat_t unavailable", "path", dir)
				continue
			}
			uid := strconv.FormatUint(uint64(stat.Uid), 10)
			if _, exists := users[uid]; exists {
				continue
			}
			u, ok := getentPasswd(uid)
			if !ok {
				u = &User{UserName: "unknown:" + uid, UID: uid, HomeDir: dir}
			}
			users[u.UID] = u
			claimed[cleaned] = struct{}{}
		}
	}
}

// sssdHomeDirGlobs reads /etc/sssd/sssd.conf and returns the set
// of glob patterns derived from fallback_homedir / override_homedir
// values. `/home/%u` is always included as a baseline. SSSD
// placeholders (per sssd.conf(5)) become `*`; `%%` collapses to a
// literal `%`. NewReplacer's longest-match wins ensures `%%u`
// resolves to the literal `%u` rather than the `%u` -> `*` rule.
// Patterns with more than MaxHomeDirGlobWildcards `*`s are dropped.
func sssdHomeDirGlobs() map[string]struct{} {
	templates := []string{"/home/%u"}
	if data, err := os.ReadFile("/etc/sssd/sssd.conf"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			if key != "fallback_homedir" && key != "override_homedir" {
				continue
			}
			// sssd.conf accepts `#`/`;` as inline comment markers.
			if i := strings.IndexAny(value, "#;"); i >= 0 {
				value = value[:i]
			}
			if v := strings.TrimSpace(value); v != "" {
				templates = append(templates, v)
			}
		}
	} else {
		slog.Debug("sssdHomeDirGlobs: sssd.conf unreadable", "err", err)
	}

	toGlob := strings.NewReplacer(
		"%%", "%",
		"%u", "*",
		"%U", "*",
		"%d", "*",
		"%f", "*",
		"%h", "*",
		"%o", "*",
		"%P", "*",
	)
	globs := make(map[string]struct{})
	for _, t := range templates {
		g := toGlob.Replace(t)
		if n := strings.Count(g, "*"); n > MaxHomeDirGlobWildcards {
			slog.Error("sssdHomeDirGlobs: skipping pattern with too many wildcards",
				"template", t, "glob", g, "wildcards", n, "max", MaxHomeDirGlobWildcards)
			continue
		}
		globs[g] = struct{}{}
	}
	return globs
}

// localGlobMatches expands glob and returns every match whose full
// path sits on a local filesystem in the allowlist. Statfs errors
// count as remote.
func localGlobMatches(glob string) []string {
	parent := wildcardParentDir(glob)
	if !isPathOnLocalFS(parent) {
		slog.Error("localGlobMatches: skipping sssd.conf home-dir glob because its parent is remote or unavailable", "path", parent, "glob", glob)
		return nil
	}
	if parent == glob {
		return []string{glob}
	}
	seg, tail := nextWildcardSegment(glob[len(parent):])
	branches, _ := filepath.Glob(parent + seg)
	var out []string
	for _, b := range branches {
		out = append(out, localGlobMatches(b+tail)...)
	}
	return out
}

// wildcardParentDir returns the directory containing the first
// wildcard segment of glob.
// `/nfs/*/*` -> `/nfs`
// A glob with no wildcard passes through unchanged.
func wildcardParentDir(glob string) string {
	i := strings.IndexAny(glob, "*?[")
	if i < 0 {
		return glob
	}
	return filepath.Dir(glob[:i])
}

// nextWildcardSegment consumes rest up to and including the
// next path segment that contains a wildcard, returning that head
// and the remainder. rest must begin with `/`.
// "/domain_*/test/*/" -> ("/domain_*", "/test/*/").
func nextWildcardSegment(rest string) (string, string) {
	i := strings.IndexAny(rest, "*?[")
	if i < 0 {
		return rest, ""
	}
	end := strings.Index(rest[i:], "/")
	if end < 0 {
		return rest, ""
	}
	return rest[:i+end], rest[i+end:]
}

// isPathOnLocalFS reports whether p sits on a filesystem in the
// persistent-local allowlist. Statfs errors count as remote. We'd
// rather skip enumeration than walk into a broken mount.
func isPathOnLocalFS(p string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		slog.Error("isPathOnLocalFS: statfs failed, treating path as remote and skipping enumeration", "path", p, "err", err)
		return false
	}
	switch uint32(st.Type) {
	case 0xEF53, // ext2/3/4
		0x9123683E, // btrfs
		0x58465342, // xfs
		0x2FC12FC1, // zfs
		0xF2F52010, // f2fs
		0x794C7630: // overlayfs (containerised/rootless /home)
		return true
	}
	return false
}
