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
	// HomeDirFindTimeout bounds each sssd home-dir glob walk.
	HomeDirFindTimeout = 5 * time.Second
	// HostReadFileTimeout bounds per-file reads of host configuration files.
	HostReadFileTimeout = 3 * time.Second
	// MaxMachineIDSize caps /etc/machine-id reads (valid file is 33 bytes).
	MaxMachineIDSize = 4 << 10 // 4 KiB
	// MaxPasswdSize caps /etc/passwd reads (~650k+ user entries).
	MaxPasswdSize = 64 << 20 // 64 MiB
	// MaxSSSDConfSize caps /etc/sssd/sssd.conf reads.
	MaxSSSDConfSize = 4 << 20 // 4 MiB
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
func NewHost(ctx context.Context) (*Host, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("this program must run as root")
	}

	cctx, cancel := context.WithTimeout(ctx, HostReadFileTimeout)
	raw, err := readFileWithCtx(cctx, "/etc/machine-id", MaxMachineIDSize)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("/etc/machine-id: %w", err)
	}
	machineId := strings.TrimSuffix(string(raw), "\n")
	if len(machineId) != 32 {
		return nil, fmt.Errorf("/etc/machine-id: expected 32 bytes, got %d", len(machineId))
	}
	h := hmac.New(sha256.New, []byte("fLhn74XaBtmouSQkBSRIAm6tbISvrf26"))
	h.Write([]byte(machineId))
	uniqueId := base64.RawStdEncoding.EncodeToString(h.Sum(nil))

	fqdn, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}

	users, err := enumerateUsers(ctx)
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
	if !isPathOnLocalFS(path) {
		return nil
	}
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
func enumerateUsers(ctx context.Context) (map[string]*User, error) {
	slog.Debug("enumerateUsers")
	cctx, cancel := context.WithTimeout(ctx, HostReadFileTimeout)
	data, err := readFileWithCtx(cctx, "/etc/passwd", MaxPasswdSize)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("/etc/passwd: %w", err)
	}
	users := make(map[string]*User)
	for line := range strings.SplitSeq(string(data), "\n") {
		if u, ok := parsePasswdLine(line); ok {
			users[u.UID] = u
		}
	}
	enrichFromJournal(ctx, users)
	enrichWithHomeDirs(ctx, users)
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
func enrichFromJournal(ctx context.Context, users map[string]*User) {
	slog.Debug("enrichFromJournal")

	names, err := recentSessionUserNames(ctx)
	if err != nil {
		slog.Error("enrichFromJournal: could not read journal", "err", err)
		return
	}

	knownNames := make(map[string]struct{}, len(users))
	for _, u := range users {
		knownNames[u.UserName] = struct{}{}
	}

	for name := range names {
		if ctx.Err() != nil {
			return
		}
		if _, ok := knownNames[name]; ok {
			continue
		}
		u, ok := getentPasswd(ctx, name)
		if !ok {
			continue
		}
		users[u.UID] = u
	}
}

// recentSessionUserNames returns the distinct USER_ID values from
// SESSION_START records in the last SessionHistoryDays.
func recentSessionUserNames(ctx context.Context) (map[string]struct{}, error) {
	cctx, cancel := context.WithTimeout(ctx, JournalctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "journalctl",
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
		if ee, ok := errors.AsType[*exec.ExitError](err); ok && len(ee.Stderr) > 0 {
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
func getentPasswd(ctx context.Context, name string) (*User, bool) {
	cctx, cancel := context.WithTimeout(ctx, GetentTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "getent", "passwd", name).Output()
	if err != nil {
		// exit code 2: user not found. This is expected on stale accounts.
		// We only output unexpected errors here.
		if ee, ok := errors.AsType[*exec.ExitError](err); !ok || ee.ExitCode() != 2 {
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
func enrichWithHomeDirs(ctx context.Context, users map[string]*User) {
	slog.Debug("enrichWithHomeDirs")
	claimed := make(map[string]struct{}, len(users))
	for _, u := range users {
		claimed[filepath.Clean(u.HomeDir)] = struct{}{}
	}
	for pattern := range sssdHomeDirGlobs(ctx) {
		ctxFind, cancel := context.WithTimeout(ctx, HomeDirFindTimeout)
		dirs, err := localGlob(ctxFind, pattern)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("localGlob timed out", "pattern", pattern, "err", err)
		}
		for _, dir := range dirs {
			if ctx.Err() != nil {
				return
			}
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
			u, ok := getentPasswd(ctx, uid)
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
func sssdHomeDirGlobs(ctx context.Context) map[string]struct{} {
	templates := []string{"/home/%u"}
	cctx, cancel := context.WithTimeout(ctx, HostReadFileTimeout)
	data, err := readFileWithCtx(cctx, "/etc/sssd/sssd.conf", MaxSSSDConfSize)
	cancel()
	if err == nil {
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

// localGlob expands an absolute glob pattern segment-by-segment, checking
// isPathOnLocalFS before reading each directory and on every matched path.
// Already-matched path prefixes are never re-parsed for glob metacharacters,
// preventing infinite recursion on filenames containing `*`, `?`, or `[`.
// Returns ctx.Err() if ctx cancels or times out.
func localGlob(ctx context.Context, pattern string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pattern = filepath.Clean(pattern)
	if !filepath.IsAbs(pattern) {
		return nil, nil
	}
	if pattern == "/" {
		if !isPathOnLocalFS("/") {
			return nil, nil
		}
		return []string{"/"}, nil
	}
	return localGlobWalk(ctx, "/", strings.Split(strings.TrimPrefix(pattern, "/"), "/"))
}

func localGlobWalk(ctx context.Context, prefix string, segments []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	i := 0
	for i < len(segments) && !strings.ContainsAny(segments[i], "*?[") {
		prefix = filepath.Join(prefix, segments[i])
		i++
	}
	segments = segments[i:]

	if !isPathOnLocalFS(prefix) {
		return nil, nil
	}
	if len(segments) == 0 {
		if _, err := os.Lstat(prefix); err != nil {
			return nil, nil
		}
		return []string{prefix}, nil
	}

	entries, err := os.ReadDir(prefix)
	if err != nil {
		return nil, nil
	}

	seg, rest := segments[0], segments[1:]
	var out []string
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if len(rest) > 0 && !e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		matched, err := filepath.Match(seg, e.Name())
		if err != nil || !matched {
			continue
		}
		child := filepath.Join(prefix, e.Name())
		if len(rest) == 0 {
			if isPathOnLocalFS(child) {
				out = append(out, child)
			}
			continue
		}
		sub, err := localGlobWalk(ctx, child, rest)
		out = append(out, sub...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

var errNonLocalFS = errors.New("path is on a non-local filesystem")

// readFileWithCtx verifies filePath resides on a local filesystem via
// isPathOnLocalFS and reads up to maxSize bytes while respecting ctx
// cancellation/deadlines.
//
// Because Go's os file operations cannot be canceled by the runtime on regular
// files (a stalled NFS/FUSE mount puts the OS thread in uninterruptible sleep),
// the open/stat/read runs in a background goroutine so select can return early
// on ctx.Done(). Note that if a kernel syscall hangs permanently, that worker
// goroutine stays blocked until the syscall finishes or the process exits.
func readFileWithCtx(ctx context.Context, filePath string, maxSize int64) ([]byte, error) {
	// Fail fast before checking mountinfo or spawning a goroutine; without this,
	// a pre-canceled ctx and a fast local read are both ready in select.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isPathOnLocalFS(filePath) {
		return nil, fmt.Errorf("%w: %s", errNonLocalFS, filePath)
	}

	type result struct {
		data []byte
		err  error
	}
	// Buffer size 1 ensures the goroutine can send and exit if ctx wins select first.
	ch := make(chan result, 1)

	go func() {
		// O_NONBLOCK prevents open() from blocking on a FIFO with no writer.
		f, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer f.Close()

		// Stat the open descriptor (not filePath) to avoid a Stat-vs-Open TOCTOU race.
		fi, err := f.Stat()
		if err != nil {
			ch <- result{err: err}
			return
		}
		if fi.IsDir() {
			ch <- result{err: fmt.Errorf("not a regular file: %s: %w", filePath, syscall.EISDIR)}
			return
		}
		// Reject FIFOs, sockets, dirs, and devices like /dev/zero before reading anything.
		if !fi.Mode().IsRegular() {
			ch <- result{err: fmt.Errorf("not a regular file: %s", filePath)}
			return
		}
		// Bail before allocating if the file already exceeds maxSize.
		if fi.Size() > maxSize {
			ch <- result{err: fmt.Errorf("file exceeds max size: %s", filePath)}
			return
		}

		// Read at most maxSize+1 bytes so a file growing mid-read still cannot OOM.
		data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
		if err != nil {
			ch <- result{err: err}
			return
		}
		if int64(len(data)) > maxSize {
			ch <- result{err: fmt.Errorf("file exceeds max size: %s", filePath)}
			return
		}
		ch <- result{data: data}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.data, res.err
	}
}

