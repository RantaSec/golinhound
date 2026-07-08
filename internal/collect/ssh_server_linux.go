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

// Collect emits CanSSH edges from authorized_keys, CanIssueCertificate
// and CanCertSSH edges from TrustedUserCAKeys + AuthorizedPrincipalsFile,
// and ForwardsKey edges from forwarded agent sockets. Returns an error
// when sshd isn't installed (or `sshd -T` failed).
func (s *SSHServerCollector) Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	sshdConfig := loadSSHDConfig()
	if sshdConfig == nil {
		return errors.New("sshd not installed")
	}

	cas, caFile := trustedUserCAKeys(sshdConfig)
	for _, ca := range cas {
		emitKeypairNode(b, ca)
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
		emitCanIssueCertificates(h, u, sshdConfig, cas, caFile, b)
		emitCanCertSSH(h, u, sshdConfig, cas, b)
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
					"AuthorizedKeysFile": file,
					"Comment":            pubKey.Comment,
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

// trustedUserCAKeys returns the CA pubkeys listed in sshd's
// TrustedUserCAKeys file and that file's path, or (nil, "") if the
// directive is unset/unreadable.
func trustedUserCAKeys(sshdConfig map[string]string) (cas []publicKey, file string) {
	slog.Debug("trustedUserCAKeys")
	file = sshdConfig["trustedusercakeys"]
	if file == "" || file == "none" {
		return nil, ""
	}
	data, err := os.ReadFile(file)
	if err != nil {
		slog.Debug("trustedUserCAKeys: TrustedUserCAKeys file could not be read", "file", file, "err", err)
		return nil, ""
	}

	for len(data) > 0 {
		pub, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			if errors.Unwrap(err) != nil {
				slog.Debug("trustedUserCAKeys: malformed line(s) ignored", "file", file, "err", err)
			}
			break
		}
		data = rest
		cas = append(cas, *newPublicKey(pub, comment))
	}
	return cas, file
}

// authorizedPrincipalsFor resolves a user's allowed principals from
// AuthorizedPrincipalsFile. With the directive unset, returns [username]
// (sshd's username-fallback rule). An empty principals slice means sshd
// would deny cert auth. This happens if the directive is set but the
// file is missing/unreadable or empty after parsing.
func authorizedPrincipalsFor(sshdConfig map[string]string, u *User) (principals []string, file string) {
	rawFile, ok := sshdConfig["authorizedprincipalsfile"]
	if !ok {
		slog.Warn("authorizedPrincipalsFor: authorizedprincipalsfile missing from sshd -T output; suppressing cert-auth edges", "userName", u.UserName)
		return nil, ""
	}
	// sshd username-fallback
	if rawFile == "none" {
		return []string{u.UserName}, ""
	}

	file = strings.ReplaceAll(rawFile, "%u", u.UserName)
	file = strings.ReplaceAll(file, "%U", u.UID)
	file = strings.ReplaceAll(file, "%h", u.HomeDir)
	data, err := os.ReadFile(file)
	// sshd denies cert auth if AuthorizedPrincipalsFile unreadable
	if err != nil {
		slog.Debug("authorizedPrincipalsFor: AuthorizedPrincipalsFile unreadable; sshd would deny", "userName", u.UserName, "file", file, "err", err)
		return nil, file
	}
	return parsePrincipalsFile(data), file
}

// parsePrincipalsFile returns the principal names from one
// AuthorizedPrincipalsFile. Per sshd(8): one principal per line, blank
// lines and #-comments ignored. Lines may begin with authorized_keys
// options (command=, principals=, etc.) — we strip those by taking the
// last whitespace-separated field on each non-comment line.
func parsePrincipalsFile(data []byte) []string {
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		out = append(out, fields[len(fields)-1])
	}
	return out
}

// emitCanIssueCertificates emits one CanIssueCertificate edge per
// (CA, user) pair. Edges omit AuthorizedPrincipalsFile under sshd's
// username-fallback rule.
func emitCanIssueCertificates(h *Host, u *User, sshdConfig map[string]string, cas []publicKey, caFile string, b *opengraph.GraphBuilder) {
	if len(cas) == 0 {
		return
	}
	principals, file := authorizedPrincipalsFor(sshdConfig, u)
	if len(principals) == 0 {
		return
	}

	props := map[string]any{
		"AuthorizedPrincipals":  principals,
		"TrustedUserCAKeysFile": caFile,
	}
	if file != "" {
		props["AuthorizedPrincipalsFile"] = file
	}
	for _, ca := range cas {
		b.AddEdge("CanIssueCertificate",
			opengraph.ByID("SSHKeyPair", ca.FingerprintSHA256),
			opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
			props)
	}
}

// emitCanCertSSH emits CanCertSSH edges from SSHCertificate nodes to a
// local SSHUser. Two flavors per (CA, user):
//
//  1. Per-principal edges: one per principal in the user's
//     AuthorizedPrincipalsFile (or [username] under sshd's
//     username-fallback rule). Selector is ByProperty(SSHCertificate,
//     CAFingerprintSHA256 + Principal=<name>) - matches the per-principal
//     split nodes ssh_client.go::emitSSHCertificateNodes produces.
//     The Principal scalar is the BloodHound match-equals workaround
//     for list-contains, see emitSSHCertificateNodes for full context.
//
//  2. One wildcard edge per CA: selector is ByProperty(SSHCertificate,
//     CAFingerprintSHA256 + WildcardPrincipal=true). This matches the
//     lone split node minted for a zero-principal cert (per
//     PROTOCOL.certkeys: "a zero-length valid principals field means
//     the certificate is valid for any principal of the specified
//     type").
func emitCanCertSSH(h *Host, u *User, sshdConfig map[string]string, cas []publicKey, b *opengraph.GraphBuilder) {
	if len(cas) == 0 {
		return
	}
	principals, file := authorizedPrincipalsFor(sshdConfig, u)
	if len(principals) == 0 {
		return
	}

	// AuthorizedPrincipals is redundant while the per-principal split gives
	// each edge its own concrete principal via the ByProperty(Principal=...)
	// selector. Re-enable once BloodHound gains a list-contains matcher and
	// the split can collapse.
	// props := map[string]any{"AuthorizedPrincipals": principals}
	props := map[string]any{}
	if file != "" {
		props["AuthorizedPrincipalsFile"] = file
	}

	end := opengraph.ByID("SSHUser", h.ReferenceUser(u.UID))
	for _, ca := range cas {
		for _, principal := range principals {
			b.AddEdge("CanCertSSH",
				opengraph.ByProperty("SSHCertificate",
					opengraph.PropEq("CAFingerprintSHA256", ca.FingerprintSHA256),
					opengraph.PropEq("Principal", principal)),
				end,
				props)
		}
		// Wildcard edge
		b.AddEdge("CanCertSSH",
			opengraph.ByProperty("SSHCertificate",
				opengraph.PropEq("CAFingerprintSHA256", ca.FingerprintSHA256),
				opengraph.PropEq("WildcardPrincipal", true)),
			end,
			props)
	}
}
