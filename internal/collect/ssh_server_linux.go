package collect

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/crypto/ssh"
)

const (
	// SSHDLoadConfigTimeout bounds `sshd -T` invocations in loadSSHDConfig.
	SSHDLoadConfigTimeout = 2 * time.Second
	// SSHLoadFwdKeyTimeout bounds `ssh-add -L` invocations in emitForwardedKey.
	SSHLoadFwdKeyTimeout = 2 * time.Second
)

// SSHServerCollector emits authorized_keys (CanSSH) and forwarded agent
// sockets (ForwardsKey). On client-only hosts (sshd absent) Collect
// returns an error; the driver logs all such early returns uniformly.
type SSHServerCollector struct {
	WaitForKeysDuration int // minutes
}

// Collect emits CanSSH edges from authorized_keys and ForwardsKey edges
// from forwarded agent sockets. Returns an error when sshd isn't
// installed (or `sshd -T` failed).
func (s *SSHServerCollector) Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	sshdConfig := loadSSHDConfig()
	if sshdConfig == nil {
		return errors.New("sshd not installed")
	}

	for _, u := range h.Users {
		// authorized_keys are consumed by sshd, so they require an
		// interactive shell and (for uid 0) PermitRootLogin allowed.
		if !isInteractiveShell(u.Shell) {
			continue
		}
		if u.UID == "0" && !rootLoginAllowed(sshdConfig) {
			continue
		}
		emitAuthorizedKeys(h, u, sshdConfig, b)
	}

	emitForwardedKeys(ctx, h, s.WaitForKeysDuration, b)
	return nil
}

// loadSSHDConfig parses the current SSHD config from "sshd -T". Returns
// nil when sshd is not installed or the command fails.
func loadSSHDConfig() map[string]string {
	slog.Debug("loadSSHDConfig")
	ctx, cancel := context.WithTimeout(context.Background(), SSHDLoadConfigTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sshd", "-T")
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		slog.Debug("loadSSHDConfig: 'sshd -T' failed; treating host as SSH client only", "err", err)
		return nil
	}

	cfg := make(map[string]string)
	for line := range strings.SplitSeq(out.String(), "\n") {
		key, value, _ := strings.Cut(line, " ")
		cfg[key] = value
	}
	return cfg
}

// rootLoginAllowed returns true when sshd would allow root pubkey login.
func rootLoginAllowed(cfg map[string]string) bool {
	switch cfg["permitrootlogin"] {
	case "yes", "without-password", "prohibit-password":
		return true
	default:
		return false
	}
}

// isInteractiveShell returns true if a shell would actually accept logins.
func isInteractiveShell(shell string) bool {
	switch filepath.Base(shell) {
	case "nologin", "false", "true", "sync":
		return false
	default:
		return true
	}
}

// emitAuthorizedKeys emits a CanSSH edge (SSHKeyPair -> SSHUser) per
// parseable key in every authorizedKeysFiles entry for u.
func emitAuthorizedKeys(h *Host, u *User, sshdConfig map[string]string, b *opengraph.GraphBuilder) {
	slog.Debug("emitAuthorizedKeys", "userName", u.UserName)
	for _, file := range authorizedKeysFiles(sshdConfig, u.UserName, u.HomeDir) {
		data, err := os.ReadFile(file)
		if err != nil {
			slog.Error("emitAuthorizedKeys: file could not be read", "userName", u.UserName, "file", file, "err", err)
			continue
		}
		for len(data) > 0 {
			pub, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				if errors.Unwrap(err) != nil {
					slog.Debug("emitAuthorizedKeys: malformed key line(s) ignored", "file", file, "err", err)
				}
				break
			}
			data = rest
			pubKey := newPublicKey(pub, comment)
			emitKeypairNode(b, *pubKey)
			b.AddEdge("CanSSH",
				opengraph.ByID("SSHKeyPair", pubKey.FingerprintSHA256),
				opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
				map[string]any{
					"FilePath": file,
					"Comment":  pubKey.Comment,
				})
		}
	}
}

// authorizedKeysFiles resolves all authorized_keys paths for a user by
// expanding %u/%h placeholders in sshd_config's AuthorizedKeysFile
// directive and verifying the path exists.
func authorizedKeysFiles(sshdConfig map[string]string, userName, userDir string) []string {
	slog.Debug("authorizedKeysFiles", "userName", userName, "userDir", userDir)
	configValues := strings.Fields(sshdConfig["authorizedkeysfile"])

	var files []string
	for _, f := range configValues {
		f = strings.ReplaceAll(f, "%u", userName)
		f = strings.ReplaceAll(f, "%h", userDir+"/")
		if !filepath.IsAbs(f) {
			f = filepath.Join(userDir, f)
		}
		fi, err := os.Stat(f)
		if err == nil && !fi.IsDir() && !slices.Contains(files, f) {
			files = append(files, f)
		}
	}
	return files
}

// emitForwardedKeys runs an fsnotify watch on /tmp/ for live agent
// sockets and emits a ForwardsKey edge for the key visible on each
// socket.
func emitForwardedKeys(ctx context.Context, h *Host, duration int, b *opengraph.GraphBuilder) {
	slog.Debug("emitForwardedKeys", "duration", duration)
	chSockets := make(chan string)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		wg.Wait()
		close(chSockets)
	}()

	go queryOpenSockets(chSockets, &wg)
	go watchNewSockets(ctx, chSockets, duration, &wg)

	for socket := range chSockets {
		emitForwardedKey(ctx, h, socket, b)
	}
}

// queryOpenSockets globs /tmp/ssh-*/agent.* once and sends every match
// into chSockets, then returns.
func queryOpenSockets(chSockets chan<- string, wg *sync.WaitGroup) {
	slog.Debug("queryOpenSockets")
	defer wg.Done()
	sockets, _ := filepath.Glob("/tmp/ssh-*/agent.*")
	for _, socket := range sockets {
		chSockets <- socket
	}
}

// watchNewSockets runs an fsnotify watch on /tmp/ for the given duration
// (minutes), forwarding every /tmp/ssh-*/agent.* socket created during
// the window into chSockets. Returns early on ctx cancellation or watcher-
// init failure (logged at Error).
func watchNewSockets(ctx context.Context, chSockets chan<- string, duration int, wg *sync.WaitGroup) {
	slog.Debug("watchNewSockets", "duration", duration)
	defer wg.Done()

	timeout := time.After(time.Duration(duration) * time.Minute)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("file system watcher could not be initialized; no new forwarded keys will be collected", "err", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add("/tmp/"); err != nil {
		slog.Error("directory '/tmp/' could not be watched; no new forwarded keys will be collected", "err", err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) && strings.HasPrefix(event.Name, "/tmp/ssh-") {
				sockets, _ := filepath.Glob(filepath.Join(event.Name, "/agent.*"))
				for _, socket := range sockets {
					chSockets <- socket
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("fsnotify", "err", err)
		case <-timeout:
			return
		case <-ctx.Done():
			return
		}
	}
}

// emitForwardedKey runs `ssh-add -L` against one forwarded agent socket
// (bounded by SSHLoadFwdKeyTimeout), pairs it with metadata about the owning
// sshd process (owner, child-process creation time, SSH_CONNECTION IP) and
// emits one ForwardsKey edge (SSHUser -> SSHKeyPair) per key visible on the
// agent. Any pre-edge failure (ssh-add error, dead sshd pid,
// missing owner, no child process) is logged at Debug and skips this
// socket.
func emitForwardedKey(ctx context.Context, h *Host, socket string, b *opengraph.GraphBuilder) {
	cctx, cancel := context.WithTimeout(ctx, SSHLoadFwdKeyTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "ssh-add", "-L")
	cmd.Env = []string{"SSH_AUTH_SOCK=" + socket}
	stdOut, err := cmd.Output()
	if err != nil {
		slog.Debug("emitForwardedKey: public key could not be retrieved from socket", "socket", socket)
		return
	}

	sshdPid, _ := strconv.ParseInt(strings.Split(filepath.Base(socket), ".")[1], 10, 32)
	sshdProcess, err := process.NewProcess(int32(sshdPid))
	if err != nil {
		slog.Debug("emitForwardedKey: SSHD process no longer exists", "sshdPid", sshdPid)
		return
	}

	// Ask the kernel directly for the sshd process's UID — gopsutil
	// reads /proc/<pid>/status. The uid must be in h.Users so
	// OSCollector.Finalize can find the display name (the sshd
	// session owner is currently logged in, so /etc/passwd or the
	// SSSD /home/ scan covered them; if neither did, skip).
	sshdUids, err := sshdProcess.Uids()
	if err != nil || len(sshdUids) == 0 {
		slog.Debug("emitForwardedKey: could not read sshd process UIDs", "sshdPid", sshdPid, "err", err)
		return
	}
	sshdUid := strconv.FormatInt(int64(sshdUids[0]), 10)
	if _, ok := h.Users[sshdUid]; !ok {
		slog.Debug("emitForwardedKey: sshd process owner not in h.Users", "sshdPid", sshdPid, "uid", sshdUid)
		return
	}

	sshdChildProcesses, err := sshdProcess.Children()
	if err != nil || len(sshdChildProcesses) == 0 {
		slog.Debug("emitForwardedKey: SSHD process does not have any children", "sshdPid", sshdPid)
		return
	}
	loginTimeEpoch, _ := sshdChildProcesses[0].CreateTime()
	loginTimeZulu := time.Unix(loginTimeEpoch/1000, 0).UTC().Format(time.RFC3339)

	var loginIp string
	sshdChildEnviron, _ := sshdChildProcesses[0].Environ()
	for _, envString := range sshdChildEnviron {
		if strings.Contains(envString, "SSH_CONNECTION") {
			loginIp = strings.Split(strings.Split(envString, "=")[1], " ")[0]
		}
	}

	for data := stdOut; len(data) > 0; {
		pub, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break
		}
		data = rest
		pubKey := newPublicKey(pub, comment)
		emitKeypairNode(b, *pubKey)
		b.AddEdge("ForwardsKey",
			opengraph.ByID("SSHUser", h.ReferenceUser(sshdUid)),
			opengraph.ByID("SSHKeyPair", pubKey.FingerprintSHA256),
			map[string]any{
				"LastLoginSocket": socket,
				"LastLoginTime":   loginTimeZulu,
				"LastLoginIP":     loginIp,
				"Comment":         pubKey.Comment,
			})
	}
}
