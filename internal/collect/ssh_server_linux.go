package collect

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// SSHDLoadConfigTimeout bounds `sshd -T` invocations in loadSSHDConfig.
	SSHDLoadConfigTimeout = 2 * time.Second
	// SSHLoadFwdKeyTimeout bounds forwarded agent socket communication in emitForwardedKey.
	SSHLoadFwdKeyTimeout = 2 * time.Second
	// MaxAuthorizedKeysSize caps authorized_keys file reads (~65k+ RSA-4096 keys).
	MaxAuthorizedKeysSize = 64 << 20 // 64 MiB
	// MaxTrustedUserCAKeysSize caps TrustedUserCAKeys file reads.
	MaxTrustedUserCAKeysSize = 8 << 20 // 8 MiB
	// MaxAuthorizedPrincipalsSize caps AuthorizedPrincipalsFile reads.
	MaxAuthorizedPrincipalsSize = 16 << 20 // 16 MiB
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
	sshdConfig, err := loadSSHDConfig(ctx)
	if err != nil {
		return err
	}

	cas, caFile := trustedUserCAKeys(ctx, sshdConfig)
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
		if err := emitAuthorizedKeys(ctx, h, u, sshdConfig, b); err != nil {
			return err
		}
		if len(cas) > 0 {
			principals, file := authorizedPrincipalsFor(ctx, sshdConfig, u)
			if len(principals) > 0 {
				emitCanIssueCertificates(h, u, cas, principals, file, caFile, b)
				emitCanCertSSH(h, u, cas, principals, file, b)
			}
		}
	}

	return emitForwardedKeys(ctx, h, s.WaitForKeysDuration, b)
}

// loadSSHDConfig parses the current SSHD config from "sshd -T".
func loadSSHDConfig(ctx context.Context) (map[string]string, error) {
	slog.Debug("loadSSHDConfig")
	cctx, cancel := context.WithTimeout(ctx, SSHDLoadConfigTimeout)
	defer cancel()

	out, err := exec.CommandContext(cctx, "sshd", "-T").Output()
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w", err)
	}

	cfg := make(map[string]string)
	for line := range strings.SplitSeq(string(out), "\n") {
		if key, value, ok := strings.Cut(line, " "); ok {
			cfg[key] = value
		}
	}
	return cfg, nil
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
// parseable key in every authorizedKeysFiles entry for u. Returns
// ctx.Err() if ctx is canceled or expired.
func emitAuthorizedKeys(ctx context.Context, h *Host, u *User, sshdConfig map[string]string, b *opengraph.GraphBuilder) error {
	slog.Debug("emitAuthorizedKeys", "userName", u.UserName)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, file := range authorizedKeysFiles(sshdConfig, u) {
		cctx, cancel := context.WithTimeout(ctx, SSHReadFileTimeout)
		data, err := readFileWithCtx(cctx, file, MaxAuthorizedKeysSize)
		cancel()
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EISDIR) && !errors.Is(err, errNonLocalFS) {
				slog.Error("emitAuthorizedKeys: file could not be read", "userName", u.UserName, "file", file, "err", err)
			}
			continue
		}
		for len(data) > 0 {
			pub, comment, opts, rest, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				if errors.Unwrap(err) != nil {
					slog.Debug("emitAuthorizedKeys: malformed key line(s) ignored", "file", file, "err", err)
				}
				break
			}
			data = rest
			pubKey := newPublicKey(pub, comment)
			emitKeypairNode(b, *pubKey)
			if slices.Contains(opts, "cert-authority") {
				principals := certAuthorityPrincipals(opts, u)
				if len(principals) > 0 {
					cas := []publicKey{*pubKey}
					emitCanIssueCertificates(h, u, cas, principals, file, "", b)
					emitCanCertSSH(h, u, cas, principals, file, b)
				}
				continue
			}
			b.AddEdge("GLH_CanSSH",
				opengraph.ByID("GLH_SSHKeyPair", pubKey.FingerprintSHA256),
				opengraph.ByID("GLH_SSHUser", h.ReferenceUser(u.UID)),
				map[string]any{
					"AuthorizedKeysFile": file,
					"Comment":            pubKey.Comment,
				})
		}
	}
	return nil
}

// authorizedKeysFiles resolves all candidate authorized_keys paths for a
// user by expanding %%/u/%U/%h placeholders in sshd_config's
// AuthorizedKeysFile directive.
func authorizedKeysFiles(sshdConfig map[string]string, u *User) []string {
	slog.Debug("authorizedKeysFiles", "userName", u.UserName, "userDir", u.HomeDir)
	replacer := strings.NewReplacer(
		"%%", "%",
		"%u", u.UserName,
		"%U", u.UID,
		"%h", u.HomeDir,
	)
	var files []string
	for raw := range strings.FieldsSeq(sshdConfig["authorizedkeysfile"]) {
		if raw == "none" {
			continue
		}
		f := replacer.Replace(raw)
		if !filepath.IsAbs(f) {
			f = filepath.Join(u.HomeDir, f)
		}
		f = filepath.Clean(f)
		if filepath.IsAbs(f) && !slices.Contains(files, f) {
			files = append(files, f)
		}
	}
	return files
}

// emitForwardedKeys collects live and newly created SSH agent sockets under
// /tmp/ and emits ForwardsKey edges for their loaded keys. Returns ctx.Err()
// if ctx is canceled or expired.
func emitForwardedKeys(ctx context.Context, h *Host, duration int, b *opengraph.GraphBuilder) error {
	slog.Debug("emitForwardedKeys", "duration", duration)
	if err := ctx.Err(); err != nil {
		return err
	}
	chSockets := make(chan string)
	var wg sync.WaitGroup
	wg.Go(func() { queryOpenSockets(ctx, chSockets) })
	if duration > 0 {
		wg.Go(func() { watchNewSockets(ctx, chSockets, duration) })
	}
	go func() {
		wg.Wait()
		close(chSockets)
	}()

	for socket := range chSockets {
		if err := emitForwardedKey(ctx, h, socket, b); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// queryOpenSockets globs /tmp/ssh-*/agent.* once and sends every match
// into chSockets, returning early if ctx is canceled.
func queryOpenSockets(ctx context.Context, chSockets chan<- string) {
	slog.Debug("queryOpenSockets")
	sockets, _ := localGlob(ctx, "/tmp/ssh-*/agent.*")
	for _, socket := range sockets {
		select {
		case chSockets <- socket:
		case <-ctx.Done():
			return
		}
	}
}

// watchNewSockets runs an fsnotify watch on /tmp/ for the given duration
// (minutes), forwarding every /tmp/ssh-*/agent.* socket created during
// the window into chSockets. Returns early on ctx cancellation, timeout,
// or watcher-init failure (logged at Error).
func watchNewSockets(ctx context.Context, chSockets chan<- string, duration int) {
	slog.Debug("watchNewSockets", "duration", duration)
	if err := ctx.Err(); err != nil {
		return
	}
	if !isPathOnLocalFS("/tmp") {
		return
	}

	wctx, cancel := context.WithTimeout(ctx, time.Duration(duration)*time.Minute)
	defer cancel()

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
			// Only care about new /tmp/ssh-*/ directories the sshd process creates
			if !event.Has(fsnotify.Create) || !strings.HasPrefix(event.Name, "/tmp/ssh-") {
				continue
			}
			if !isPathOnLocalFS(event.Name) {
				continue
			}
			// Wait up to 100ms for the sshd process to create agent.* sockets in the new directory
			var sockets []string
			for range 10 {
				sockets, _ = localGlobWalk(wctx, event.Name, []string{"agent.*"})
				if len(sockets) > 0 {
					break
				}
				select {
				case <-time.After(10 * time.Millisecond):
				case <-wctx.Done():
					return
				}
			}
			// Send any found sockets to the channel, respecting context cancellation
			for _, socket := range sockets {
				select {
				case chSockets <- socket:
				case <-wctx.Done():
					return
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("fsnotify", "err", err)
		case <-wctx.Done():
			return
		}
	}
}

// emitForwardedKey queries a forwarded agent socket for loaded public keys
// (bounded by SSHLoadFwdKeyTimeout), pairs each with metadata from the socket
// and owning sshd process (owner, socket creation time, peer IP) and
// emits one ForwardsKey edge (SSHUser -> SSHKeyPair) per key visible on the
// agent. Returns ctx.Err() on cancellation; any pre-edge failure (missing
// owner, unresolvable peer IP, or agent query error) logs at Debug and
// returns nil.
func emitForwardedKey(ctx context.Context, h *Host, socket string, b *opengraph.GraphBuilder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isPathOnLocalFS(socket) {
		return nil
	}
	fi, err := os.Lstat(socket)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	owner := h.fileOwner(socket)
	if owner == nil {
		return nil
	}

	var loginIp string
	if _, pidStr, ok := strings.CutLast(filepath.Base(socket), "."); ok {
		loginIp = procRemoteIP(pidStr)
	}
	if loginIp == "" {
		slog.Debug("emitForwardedKey: could not resolve remote IP for sshd process", "socket", socket)
		return nil
	}

	keys, err := agentListKeys(ctx, socket)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Debug("emitForwardedKey: public key could not be retrieved from socket", "socket", socket, "err", err)
		return nil
	}

	loginTimeZulu := fi.ModTime().UTC().Format(time.RFC3339)
	for _, k := range keys {
		pubKey := newPublicKey(k, k.Comment)
		emitKeypairNode(b, *pubKey)
		b.AddEdge("GLH_ForwardsKey",
			opengraph.ByID("GLH_SSHUser", h.ReferenceUser(owner.UID)),
			opengraph.ByID("GLH_SSHKeyPair", pubKey.FingerprintSHA256),
			map[string]any{
				"LastLoginSocket": socket,
				"LastLoginTime":   loginTimeZulu,
				"LastLoginIP":     loginIp,
				"Comment":         pubKey.Comment,
			})
	}
	return nil
}

// agentListKeys queries an SSH agent UNIX domain socket for loaded keys,
// bounded by SSHLoadFwdKeyTimeout and parent ctx cancellation.
func agentListKeys(ctx context.Context, socket string) ([]*agent.Key, error) {
	cctx, cancel := context.WithTimeout(ctx, SSHLoadFwdKeyTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(cctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// If cctx is canceled, close the connection to unblock agent.NewClient(conn).List().
	stop := context.AfterFunc(cctx, func() { _ = conn.Close() })
	defer stop()

	keys, err := agent.NewClient(conn).List()
	if err != nil && cctx.Err() != nil {
		return nil, cctx.Err()
	}
	return keys, err
}

// procRemoteIP resolves the remote peer IP of the lowest-FD established TCP
// socket held by pid via /proc/<pid>/fd and /proc/<pid>/net/tcp{,6}.
// Selecting the lowest FD ensures the initial SSH client connection (typically
// fd 3/4) always wins over later port-forwarding channels (-L/-D).
func procRemoteIP(pid string) string {
	// List all open file descriptors for pid. Non-numeric or exited pids
	// fail here immediately without touching /proc/<pid>/net/tcp{,6}.
	entries, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		return ""
	}

	// Build a lookup from socket symlink target ("socket:[<inode>]") to its lowest FD.
	inodeFD := make(map[string]int, len(entries))
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		target, err := os.Readlink("/proc/" + pid + "/fd/" + e.Name())
		// Skip non-socket FDs (files, pipes, /dev/pts/*).
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		if prev, exists := inodeFD[target]; !exists || fd < prev {
			inodeFD[target] = fd
		}
	}

	// Bail early before reading /proc/<pid>/net/tcp{,6} if the process has no open sockets.
	if len(inodeFD) == 0 {
		return ""
	}

	// Initialize bestFD to MaxInt so any real FD (< MaxInt) beats it.
	bestFD := math.MaxInt
	var bestIP string
	for _, table := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile("/proc/" + pid + "/net/" + table)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			fields := strings.Fields(line)
			// Kernel table columns: [0]=sl [1]=local_address [2]=rem_address
			// [3]=st ("01" = TCP_ESTABLISHED) ... [9]=inode.
			if len(fields) < 10 || fields[3] != "01" {
				continue
			}

			// Look up this socket's FD and skip if we already found a lower FD.
			fd, ok := inodeFD["socket:["+fields[9]+"]"]
			if !ok || fd >= bestFD {
				continue
			}

			// rem_address is HEX_IP:HEX_PORT; decode HEX_IP and record it as
			// the new best candidate.
			if hexIP, _, ok := strings.Cut(fields[2], ":"); ok {
				if ip := parseProcHexIP(hexIP); ip != "" {
					bestFD = fd
					bestIP = ip
				}
			}
		}
	}
	return bestIP
}

// parseProcHexIP decodes a little-endian 32-bit word hex IP from
// /proc/net/tcp{,6} into its canonical IPv4 or IPv6 string.
func parseProcHexIP(hexIP string) string {
	raw, err := hex.DecodeString(hexIP)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return ""
	}
	for i := 0; i < len(raw); i += 4 {
		slices.Reverse(raw[i : i+4])
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return ""
	}
	return addr.Unmap().String()
}

// trustedUserCAKeys returns the CA pubkeys listed in sshd's
// TrustedUserCAKeys file and that file's path, or (nil, "") if the
// directive is unset/unreadable.
func trustedUserCAKeys(ctx context.Context, sshdConfig map[string]string) (cas []publicKey, file string) {
	slog.Debug("trustedUserCAKeys")
	file = sshdConfig["trustedusercakeys"]
	if file == "" || file == "none" {
		return nil, ""
	}
	file = filepath.Clean(file)
	if !filepath.IsAbs(file) {
		return nil, ""
	}
	cctx, cancel := context.WithTimeout(ctx, SSHReadFileTimeout)
	defer cancel()

	data, err := readFileWithCtx(cctx, file, MaxTrustedUserCAKeysSize)
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
func authorizedPrincipalsFor(ctx context.Context, sshdConfig map[string]string, u *User) (principals []string, file string) {
	rawFile := sshdConfig["authorizedprincipalsfile"]
	if rawFile == "" {
		slog.Warn("authorizedPrincipalsFor: authorizedprincipalsfile missing from sshd -T output; suppressing cert-auth edges", "userName", u.UserName)
		return nil, ""
	}
	// sshd username-fallback
	if rawFile == "none" {
		return []string{u.UserName}, ""
	}

	file = strings.NewReplacer(
		"%%", "%",
		"%u", u.UserName,
		"%U", u.UID,
		"%h", u.HomeDir,
	).Replace(rawFile)
	if !filepath.IsAbs(file) {
		file = filepath.Join(u.HomeDir, file)
	}
	file = filepath.Clean(file)
	if !filepath.IsAbs(file) {
		return nil, ""
	}

	cctx, cancel := context.WithTimeout(ctx, SSHReadFileTimeout)
	defer cancel()

	data, err := readFileWithCtx(cctx, file, MaxAuthorizedPrincipalsSize)
	// sshd denies cert auth if AuthorizedPrincipalsFile unreadable
	if err != nil {
		slog.Debug("authorizedPrincipalsFor: AuthorizedPrincipalsFile unreadable; sshd would deny", "userName", u.UserName, "file", file, "err", err)
		return nil, file
	}
	return parsePrincipalsFile(data), file
}

// parsePrincipalsFile returns the principal names from one
// AuthorizedPrincipalsFile. One principal per line, blank lines and
// #-comments ignored. Lines may begin with authorized_keys options
// (command=, principals=, etc.) — we strip those by taking the last
// whitespace-separated field on each non-comment line.
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

// certAuthorityPrincipals resolves the principals option in a
// cert-authority authorized_keys entry. With the option unset, returns
// [username] (sshd's username-fallback rule). An empty principals slice
// (from principals="") means sshd would deny cert auth.
func certAuthorityPrincipals(opts []string, u *User) []string {
	for _, o := range opts {
		if v, ok := strings.CutPrefix(o, "principals=\""); ok {
			v = strings.TrimSuffix(v, "\"")
			if v == "" {
				return nil
			}
			return strings.Split(v, ",")
		}
	}
	return []string{u.UserName}
}

// emitCanIssueCertificates emits one CanIssueCertificate edge per
// (CA, user) pair.
func emitCanIssueCertificates(h *Host, u *User, cas []publicKey, principals []string, principalsFile, caFile string, b *opengraph.GraphBuilder) {
	props := map[string]any{
		"AuthorizedPrincipals": principals,
	}
	if caFile != "" {
		props["TrustedUserCAKeysFile"] = caFile
	}
	if principalsFile != "" {
		props["AuthorizedPrincipalsFile"] = principalsFile
	}
	for _, ca := range cas {
		b.AddEdge("GLH_CanIssueCertificate",
			opengraph.ByID("GLH_SSHKeyPair", ca.FingerprintSHA256),
			opengraph.ByID("GLH_SSHUser", h.ReferenceUser(u.UID)),
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
func emitCanCertSSH(h *Host, u *User, cas []publicKey, principals []string, file string, b *opengraph.GraphBuilder) {
	// AuthorizedPrincipals is redundant while the per-principal split gives
	// each edge its own concrete principal via the ByProperty(Principal=...)
	// selector. Re-enable once BloodHound gains a list-contains matcher and
	// the split can collapse.
	// props := map[string]any{"AuthorizedPrincipals": principals}
	props := map[string]any{}
	if file != "" {
		props["AuthorizedPrincipalsFile"] = file
	}

	end := opengraph.ByID("GLH_SSHUser", h.ReferenceUser(u.UID))
	for _, ca := range cas {
		for _, principal := range principals {
			b.AddEdge("GLH_CanCertSSH",
				opengraph.ByProperty("GLH_SSHCertificate",
					opengraph.PropEq("CAFingerprintSHA256", ca.FingerprintSHA256),
					opengraph.PropEq("Principal", principal)),
				end,
				props)
		}
		// Wildcard edge
		b.AddEdge("GLH_CanCertSSH",
			opengraph.ByProperty("GLH_SSHCertificate",
				opengraph.PropEq("CAFingerprintSHA256", ca.FingerprintSHA256),
				opengraph.PropEq("WildcardPrincipal", true)),
			end,
			props)
	}
}
