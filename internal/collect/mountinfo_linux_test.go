package collect

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

type capturedLog struct {
	Level   slog.Level
	Message string
	Attrs   map[string]any
}

type testLogHandler struct {
	mu      sync.Mutex
	records []capturedLog
}

func (h *testLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := make(map[string]any)
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, capturedLog{
		Level:   r.Level,
		Message: r.Message,
		Attrs:   attrs,
	})
	h.mu.Unlock()
	return nil
}

func (h *testLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *testLogHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *testLogHandler) warnings() []capturedLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []capturedLog
	for _, r := range h.records {
		if r.Level == slog.LevelWarn {
			out = append(out, r)
		}
	}
	return out
}

func (h *testLogHandler) errors() []capturedLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []capturedLog
	for _, r := range h.records {
		if r.Level == slog.LevelError {
			out = append(out, r)
		}
	}
	return out
}

func installTestLogger(t *testing.T) *testLogHandler {
	t.Helper()
	prev := slog.Default()
	h := &testLogHandler{}
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

func setTestFSGuard(t *testing.T, mounts []mountEntry) {
	t.Helper()
	prev := activeFSGuard.Load()
	activeFSGuard.Store(&fsGuard{
		mounts: mounts,
	})
	t.Cleanup(func() { activeFSGuard.Store(prev) })
}

func TestParseMountInfo(t *testing.T) {
	raw := strings.Join([]string{
		"1 1 0:1 / / rootfs rw - rootfs rootfs rw",
		"22 1 0:21 / / overlay rw,relatime shared:1 - overlay overlay rw,lowerdir=/a",
		"23 22 0:5 / /proc rw,nosuid,nodev,noexec - proc proc rw",
		"24 22 253:1 / /home rw,relatime - xfs /dev/mapper/vg-home rw",
		"25 22 0:31 / /etc/ssl/certs/ca.crt ro - tmpfs  rw,uid=1000",
		`26 22 0:42 / /mnt/remote\040share rw,relatime - nfs4 server:/export/my\040share rw`,
		"27 22 0:43 / /mnt/auto rw - autofs systemd-1 rw",
		"28 27 0:44 / /mnt/auto rw - nfs4 nas:/auto rw",
		"29 22 0:45 / /shared rw - virtiofs shared rw",
		"30 22 0:46 / /mnt/win9p rw - 9p drvfs rw",
		"31 22 0:47 / /mnt/sshfs rw - fuse.sshfs user@host:/ rw",
		"32 22 0:48 / /mnt/smb rw - cifs //nas/share rw",
	}, "\n")

	mounts := parseMountInfo(raw)
	if len(mounts) != 12 {
		t.Fatalf("expected 12 mount entries, got %d", len(mounts))
	}
	if mounts[5].mountPoint != "/mnt/remote share" || mounts[5].fsType != "nfs4" {
		t.Fatalf("unexpected escaped mount entry: %+v", mounts[5])
	}
	if mounts[4].mountPoint != "/etc/ssl/certs/ca.crt" || mounts[4].fsType != "tmpfs" {
		t.Fatalf("unexpected empty-source mount entry: %+v", mounts[4])
	}
}

func TestCheckPathOnLocalFS(t *testing.T) {
	tmp := t.TempDir()
	localFile := filepath.Join(tmp, "local.key")
	if err := os.WriteFile(localFile, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	localLink := filepath.Join(tmp, "local_link.key")
	if err := os.Symlink(localFile, localLink); err != nil {
		t.Fatal(err)
	}

	remoteMount := filepath.Join(tmp, "nfs_mount")
	remoteTarget := filepath.Join(remoteMount, "secret.key")
	linkToRemote := filepath.Join(tmp, "escape_link.key")
	if err := os.Symlink(remoteTarget, linkToRemote); err != nil {
		t.Fatal(err)
	}
	relLinkToRemote := filepath.Join(tmp, "rel_escape_link.key")
	if err := os.Symlink(filepath.Join("nfs_mount", "secret.key"), relLinkToRemote); err != nil {
		t.Fatal(err)
	}

	// Symlink loop on local FS must fail closed cleanly.
	loopA := filepath.Join(tmp, "loopA")
	loopB := filepath.Join(tmp, "loopB")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatal(err)
	}

	autoMount := filepath.Join(tmp, "auto")
	virtioMount := filepath.Join(tmp, "virtiofs")
	ninePMount := filepath.Join(tmp, "9p")
	bcacheMount := filepath.Join(tmp, "bcache")
	sshfsMount := filepath.Join(tmp, "sshfs")
	cifsMount := filepath.Join(tmp, "cifs")

	mounts := []mountEntry{
		{mountPoint: "/", fsType: "rootfs"},
		{mountPoint: "/", fsType: "overlay"},
		{mountPoint: tmp, fsType: "ext4"},
		{mountPoint: remoteMount, fsType: "nfs4"},
		{mountPoint: remoteMount + "/nested_local", fsType: "ext4"},
		{mountPoint: autoMount, fsType: "autofs"},
		{mountPoint: autoMount, fsType: "nfs4"},
		{mountPoint: virtioMount, fsType: "virtiofs"},
		{mountPoint: ninePMount, fsType: "9p"},
		{mountPoint: bcacheMount, fsType: "bcachefs"},
		{mountPoint: sshfsMount, fsType: "fuse.sshfs"},
		{mountPoint: cifsMount, fsType: "cifs"},
	}

	tests := []struct {
		name      string
		path      string
		wantLocal bool
		wantMP    string
		wantFS    string
	}{
		{"local file", localFile, true, "", ""},
		{"local missing file", filepath.Join(tmp, "does_not_exist"), true, "", ""},
		{"local symlink", localLink, true, "", ""},
		{"prefix boundary near remote", remoteMount + "_local/file", true, "", ""},
		{"remote path", remoteTarget, false, remoteMount, "nfs4"},
		{"nested local under remote stops at remote parent", filepath.Join(remoteMount, "nested_local", "file"), false, remoteMount, "nfs4"},
		{"symlink to remote", linkToRemote, false, remoteMount, "nfs4"},
		{"relative symlink to remote", relLinkToRemote, false, remoteMount, "nfs4"},
		{"autofs overmounted by nfs4", filepath.Join(autoMount, "dir"), false, autoMount, "nfs4"},
		{"virtiofs allowed", filepath.Join(virtioMount, "file"), true, "", ""},
		{"9p allowed", filepath.Join(ninePMount, "file"), true, "", ""},
		{"bcachefs allowed", filepath.Join(bcacheMount, "file"), true, "", ""},
		{"fuse.sshfs blocked", filepath.Join(sshfsMount, "id_rsa"), false, sshfsMount, "fuse.sshfs"},
		{"cifs blocked", filepath.Join(cifsMount, "krb5.keytab"), false, cifsMount, "cifs"},
		{"relative path rejected", "relative/path", false, "", "relative path"},
		{"local symlink loop fails closed", loopA, false, loopB, "too many symlinks"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLocal, gotMP, gotFS := checkPathOnLocalFS(tc.path, mounts)
			if gotLocal != tc.wantLocal || gotMP != tc.wantMP || gotFS != tc.wantFS {
				t.Fatalf("checkPathOnLocalFS(%q) = (%v, %q, %q), want (%v, %q, %q)",
					tc.path, gotLocal, gotMP, gotFS, tc.wantLocal, tc.wantMP, tc.wantFS)
			}
		})
	}
}

func TestReadFileWithCtx_RemoteFS(t *testing.T) {
	tmp := t.TempDir()
	remoteDir := filepath.Join(tmp, "nfs")
	if err := os.Mkdir(remoteDir, 0755); err != nil {
		t.Fatal(err)
	}
	remoteFile := filepath.Join(remoteDir, "secret.txt")
	if err := os.WriteFile(remoteFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkFile := filepath.Join(tmp, "link_secret.txt")
	if err := os.Symlink(remoteFile, symlinkFile); err != nil {
		t.Fatal(err)
	}

	mounts := []mountEntry{
		{mountPoint: "/", fsType: "ext4"},
		{mountPoint: remoteDir, fsType: "nfs4"},
	}

	logs := installTestLogger(t)
	setTestFSGuard(t, mounts)

	if _, err := readFileWithCtx(context.Background(), remoteFile, 1024); !errors.Is(err, errNonLocalFS) {
		t.Fatalf("expected errNonLocalFS for remoteFile, got %v", err)
	}
	if _, err := readFileWithCtx(context.Background(), symlinkFile, 1024); !errors.Is(err, errNonLocalFS) {
		t.Fatalf("expected errNonLocalFS for symlinkFile, got %v", err)
	}
	if warns := logs.warnings(); len(warns) != 2 {
		t.Fatalf("expected 2 warnings (one per skipped filepath), got %d: %+v", len(warns), warns)
	}
}

func TestCollectors_RemoteFSProtectionAndWarnings(t *testing.T) {
	tmp := t.TempDir()
	remoteHome := filepath.Join(tmp, "nfs_home")
	localHome := filepath.Join(tmp, "local_home")
	if err := os.MkdirAll(filepath.Join(remoteHome, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(localHome, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}

	// Real ed25519 pubkey line for authorized_keys tests.
	pubLine := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example\n")
	if err := os.WriteFile(filepath.Join(remoteHome, ".ssh", "authorized_keys"), pubLine, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localHome, ".ssh", "authorized_keys"), pubLine, 0600); err != nil {
		t.Fatal(err)
	}

	// Keytab walk fixtures: one local subdir, one remote subdir.
	keytabRoot := filepath.Join(tmp, "keytabs")
	localKTDir := filepath.Join(keytabRoot, "local")
	remoteKTDir := filepath.Join(keytabRoot, "remote")
	if err := os.MkdirAll(localKTDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(remoteKTDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localKTDir, "a.keytab"), []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteKTDir, "b.keytab"), []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}

	mounts := []mountEntry{
		{mountPoint: "/", fsType: "ext4"},
		{mountPoint: remoteHome, fsType: "nfs4"},
		{mountPoint: remoteKTDir, fsType: "cifs"},
	}

	logs := installTestLogger(t)
	setTestFSGuard(t, mounts)

	h := &Host{
		uniqueId: "host1",
		FQDN:     "host1.local",
		Users: map[string]*User{
			"1001": {UserName: "remoteuser", UID: "1001", HomeDir: remoteHome, Shell: "/bin/bash"},
			"1002": {UserName: "localuser", UID: "1002", HomeDir: localHome, Shell: "/bin/bash"},
		},
		referencedUsers: make(map[string]struct{}),
	}

	// 1. authorized_keys protection (SSHServerCollector.emitAuthorizedKeys)
	b := opengraph.NewGraphBuilder()
	sshdCfg := map[string]string{"authorizedkeysfile": ".ssh/authorized_keys"}
	if err := emitAuthorizedKeys(context.Background(), h, h.Users["1001"], sshdCfg, b); err != nil {
		t.Fatalf("emitAuthorizedKeys(remoteuser) failed: %v", err)
	}
	if err := emitAuthorizedKeys(context.Background(), h, h.Users["1002"], sshdCfg, b); err != nil {
		t.Fatalf("emitAuthorizedKeys(localuser) failed: %v", err)
	}
	if _, ok := h.referencedUsers["1001"]; ok {
		t.Fatalf("expected remoteuser authorized_keys to be skipped")
	}
	if _, ok := h.referencedUsers["1002"]; !ok {
		t.Fatalf("expected localuser authorized_keys to be collected")
	}
	if errs := logs.errors(); len(errs) != 0 {
		t.Fatalf("expected no slog.Error logs for skipped remote authorized_keys, got %+v", errs)
	}

	// 2. privateKeysFiles warning on remote .ssh dir
	if files := privateKeysFiles(remoteHome); len(files) != 0 {
		t.Fatalf("expected no private key files from remoteHome, got %v", files)
	}

	// 3. trustedUserCAKeys & authorizedPrincipalsFor protection
	caFile := filepath.Join(remoteHome, "ca.pub")
	if err := os.WriteFile(caFile, pubLine, 0600); err != nil {
		t.Fatal(err)
	}
	if cas, _ := trustedUserCAKeys(context.Background(), map[string]string{"trustedusercakeys": caFile}); len(cas) != 0 {
		t.Fatalf("expected remote TrustedUserCAKeys to be skipped")
	}
	if principals, _ := authorizedPrincipalsFor(context.Background(), map[string]string{"authorizedprincipalsfile": "%h/.ssh/principals"}, h.Users["1001"]); len(principals) != 0 {
		t.Fatalf("expected remote AuthorizedPrincipalsFile to be skipped")
	}

	// 4. findKeytabFiles skips remoteKTDir with warning, collects localKTDir
	chKeytabs := make(chan string, 10)
	if err := findKeytabFiles(context.Background(), chKeytabs, keytabRoot, 2); err != nil {
		t.Fatalf("findKeytabFiles failed: %v", err)
	}
	close(chKeytabs)
	var keytabs []string
	for kt := range chKeytabs {
		keytabs = append(keytabs, kt)
	}
	if len(keytabs) != 1 || keytabs[0] != filepath.Join(localKTDir, "a.keytab") {
		t.Fatalf("unexpected keytabs collected: %v", keytabs)
	}

	// 5. localGlob skips remote parent
	globs, err := localGlob(context.Background(), filepath.Join(remoteHome, "*"))
	if err != nil || len(globs) != 0 {
		t.Fatalf("expected remote localGlob to skip cleanly, got (%v, %v)", globs, err)
	}

	// 6. fileOwner refuses remote paths without calling os.Stat
	if owner := h.fileOwner(filepath.Join(remoteHome, ".ssh", "authorized_keys")); owner != nil {
		t.Fatalf("expected fileOwner on remote path to return nil, got %+v", owner)
	}

	warns := logs.warnings()
	if len(warns) < 6 {
		t.Fatalf("expected warnings for every skipped remote path, got %d: %+v", len(warns), warns)
	}

	// 7. Symlinked private key inside local ~/.ssh pointing to remote FS is blocked with warning
	remoteKey := filepath.Join(remoteHome, "id_remote")
	if err := os.WriteFile(remoteKey, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(remoteKey, filepath.Join(localHome, ".ssh", "id_symlink")); err != nil {
		t.Fatal(err)
	}
	logsKey := installTestLogger(t)
	if err := emitPrivateKeys(context.Background(), h, h.Users["1002"], b, false); err != nil {
		t.Fatalf("emitPrivateKeys failed: %v", err)
	}
	if len(logsKey.warnings()) != 1 {
		t.Fatalf("expected 1 warning for symlinked private key to remote FS, got %+v", logsKey.warnings())
	}

	// 8. emitForwardedKey skips remote socket path with warning
	logsSock := installTestLogger(t)
	if err := emitForwardedKey(context.Background(), h, filepath.Join(remoteHome, "agent.123"), b); err != nil {
		t.Fatalf("emitForwardedKey failed: %v", err)
	}
	if len(logsSock.warnings()) != 1 {
		t.Fatalf("expected 1 warning for remote socket path, got %+v", logsSock.warnings())
	}
}

func TestLocalGlob(t *testing.T) {
	tmp := t.TempDir()
	localSub := filepath.Join(tmp, "ssh-local")
	metaSub := filepath.Join(tmp, "ssh-*[1]")
	remoteSub := filepath.Join(tmp, "ssh-remote")
	for _, d := range []string{localSub, metaSub, remoteSub} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	localAgent := filepath.Join(localSub, "agent.1")
	metaAgent := filepath.Join(metaSub, "agent.*")
	remoteAgent := filepath.Join(remoteSub, "agent.2")
	for _, f := range []string{localAgent, metaAgent, remoteAgent} {
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	linkAgent := filepath.Join(localSub, "agent.link")
	if err := os.Symlink(remoteAgent, linkAgent); err != nil {
		t.Fatal(err)
	}

	mounts := []mountEntry{
		{mountPoint: "/", fsType: "ext4"},
		{mountPoint: remoteSub, fsType: "nfs4"},
	}
	logs := installTestLogger(t)
	setTestFSGuard(t, mounts)

	got, err := localGlob(context.Background(), filepath.Join(tmp, "ssh-*", "agent.*"))
	if err != nil {
		t.Fatalf("localGlob failed: %v", err)
	}
	if len(got) != 2 || got[0] != metaAgent || got[1] != localAgent {
		t.Fatalf("unexpected localGlob matches: got %v, want [%s %s]", got, metaAgent, localAgent)
	}
	if warns := logs.warnings(); len(warns) != 2 {
		t.Fatalf("expected 2 warnings (remoteSub and linkAgent), got %d: %+v", len(warns), warns)
	}

	// Literal (non-wildcard) patterns: existing local matches, missing local returns empty without warning.
	litLogs := installTestLogger(t)
	gotLit, err := localGlob(context.Background(), localAgent)
	if err != nil || len(gotLit) != 1 || gotLit[0] != localAgent {
		t.Fatalf("expected literal local match, got (%v, %v)", gotLit, err)
	}
	gotMissing, err := localGlob(context.Background(), filepath.Join(tmp, "missing"))
	if err != nil || len(gotMissing) != 0 {
		t.Fatalf("expected missing literal path to return empty, got (%v, %v)", gotMissing, err)
	}
	if warns := litLogs.warnings(); len(warns) != 0 {
		t.Fatalf("expected 0 warnings for missing local literal path, got %+v", warns)
	}
}

func TestReadProcMountInfo_Live(t *testing.T) {
	mounts, err := readProcMountInfo()
	if err != nil {
		t.Fatalf("readProcMountInfo failed: %v", err)
	}
	if len(mounts) == 0 {
		t.Fatalf("expected non-empty live mountinfo entries")
	}
	for _, p := range []string{"/tmp", "/etc/passwd", "/etc/machine-id"} {
		if ok, mp, fsType := checkPathOnLocalFS(p, mounts); !ok {
			t.Fatalf("expected live path %q to be local, got mountPoint=%q fsType=%q", p, mp, fsType)
		}
	}
}
