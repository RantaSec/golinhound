package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// Timeouts for Kerberos artifact discovery and parsing.
const (
	CredentialCacheLoadTimeout = 3 * time.Second
	KeytabFindTimeout          = 5 * time.Second
	KeytabLoadTimeout          = 3 * time.Second
)

// ADCollector emits Active Directory Kerberos artifacts: keytab files
// (HasKeytab edges) and ticket caches with valid TGTs (HasTGT edges).
// Endpoint nodes for AD principals dangle by design; downstream
// BloodHound merge resolves them at ingest by `match_by: name`.
type ADCollector struct{}

// Collect walks well-known keytab and ccache locations, emitting HasKeytab
// and HasTGT edges from the host's SSHComputer to each referenced AD
// principal. Tickets that are expired and non-renewable are dropped.
func (c *ADCollector) Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	if err := emitKeytabs(ctx, h, b); err != nil {
		return err
	}
	if err := emitTGTs(ctx, h, b); err != nil {
		return err
	}
	return nil
}

// emitKeytabs walks /etc/ (depth 2) and /home/ (depth 1) in parallel for
// *.keytab files, loads each, and emits one HasKeytab edge per principal
// entry. The find walk is bounded by KeytabFindTimeout; each load has an
// independent KeytabLoadTimeout so a slow/stuck file doesn't impact the
// rest.
func emitKeytabs(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctxFind, cancel := context.WithTimeout(ctx, KeytabFindTimeout)
	defer cancel()

	var wg sync.WaitGroup
	chKeytabs := make(chan string)

	wg.Go(func() {
		if err := findKeytabFiles(ctxFind, chKeytabs, "/etc/", 2); err != nil && ctx.Err() == nil {
			slog.Warn("findKeytabFiles timed out", "root", "/etc/", "err", err)
		}
	})
	wg.Go(func() {
		if err := findKeytabFiles(ctxFind, chKeytabs, "/home/", 1); err != nil && ctx.Err() == nil {
			slog.Warn("findKeytabFiles timed out", "root", "/home/", "err", err)
		}
	})

	go func() {
		wg.Wait()
		close(chKeytabs)
	}()

	for file := range chKeytabs {
		owner := h.fileOwner(file)
		if owner == nil {
			continue
		}
		ctxLoad, cancelLoad := context.WithTimeout(ctx, KeytabLoadTimeout)
		entries, err := loadKeytab(ctxLoad, file)
		cancelLoad()
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			if !errors.Is(err, errNonLocalFS) {
				slog.Error("could not load keytab", "file", file, "err", err)
			}
		}
		for _, entry := range entries {
			emitHasKeytabEdge(h, b, owner, file, entry.Principal, entry.Realm)
		}
	}
	return ctx.Err()
}

// emitHasKeytabEdge emits one HasKeytab edge from the SSHUser that
// owns the keytab file to the principal (resolved to a BloodHound
// node name). The end node kind is User for principals containing
// "@", Computer otherwise. Principals that don't fit a known shape
// (see PrincipalToBloodhoundName) are debug-logged and dropped.
func emitHasKeytabEdge(h *Host, b *opengraph.GraphBuilder, owner *User, filePath, principal, realm string) {
	name, err := PrincipalToBloodhoundName(principal, realm)
	if err != nil {
		slog.Debug("emitHasKeytabEdge: PrincipalToBloodhoundName failed", "err", err)
		return
	}
	endKind := "User"
	if !strings.Contains(name, "@") {
		endKind = "Computer"
	}
	b.AddEdge("GLH_HasKeytab",
		opengraph.ByID("GLH_SSHUser", h.ReferenceUser(owner.UID)),
		opengraph.ByProperty(endKind, opengraph.PropEq("name", name)),
		map[string]any{"KeytabFile": filePath})
}

// findKeytabFiles walks rootDir up to maxDepth levels, sending every
// *.keytab path it finds into chKeytabs. Per-entry walk errors are
// ignored so the walk continues; returns ctx.Err() if ctx cancels or
// times out.
func findKeytabFiles(ctx context.Context, chKeytabs chan<- string, rootDir string, maxDepth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rootDir = filepath.Clean(rootDir)
	if !isPathOnLocalFS(rootDir) {
		return nil
	}
	rootDepth := strings.Count(rootDir, string(os.PathSeparator))

	return filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.Count(path, string(os.PathSeparator))-rootDepth > maxDepth {
				return filepath.SkipDir
			}
			if path != rootDir && !isPathOnLocalFS(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() && d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		if filepath.Ext(d.Name()) == ".keytab" {
			select {
			case chKeytabs <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
}


// emitTGTs iterates every on-disk ticket cache (findFileTicketCaches),
// loads each, and emits one HasTGT edge per Ticket Granting Ticket that
// has not yet expired beyond its renewal window. Each load has an
// independent CredentialCacheLoadTimeout derived from ctx so a slow/stuck
// file doesn't impact the rest, while ctx cancellation aborts promptly.
func emitTGTs(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, cacheFile := range findFileTicketCaches(ctx) {
		if err := emitTicketCache(ctx, h, b, cacheFile, time.Now()); err != nil {
			return err
		}
	}
	// Not yet implemented; left here for visibility.
	findKCMTicketCaches()
	findKeyringTicketCaches()
	return ctx.Err()
}

func emitTicketCache(ctx context.Context, h *Host, b *opengraph.GraphBuilder, cacheFile string, now time.Time) error {
	owner := h.fileOwner(cacheFile)
	if owner == nil {
		return nil
	}
	ctxLoad, cancelLoad := context.WithTimeout(ctx, CredentialCacheLoadTimeout)
	credsList, err := loadCCache(ctxLoad, cacheFile)
	cancelLoad()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err != nil {
		if !errors.Is(err, errNonLocalFS) {
			slog.Error("could not load Kerberos ticket cache", "cacheFile", cacheFile, "err", err)
		}
	}
	for _, creds := range credsList {
		// only true TGTs (krbtgt/...) become HasTGT edges
		if svc, rest, ok := strings.Cut(creds.ServerPrincipal, "/"); !ok || !strings.EqualFold(svc, "krbtgt") || rest == "" {
			continue
		}
		// expired AND non-renewable: drop
		if now.After(creds.EndTime) && now.After(creds.RenewTill) {
			continue
		}
		emitHasTGTEdge(h, b, owner, cacheFile, creds)
	}
	return nil
}

// emitHasTGTEdge emits one HasTGT edge from the SSHUser that owns
// the ccache file to the client principal of creds (resolved via
// PrincipalToBloodhoundName). Edge properties carry the ticket's
// StartTime/EndTime/RenewTime in RFC3339.
func emitHasTGTEdge(h *Host, b *opengraph.GraphBuilder, owner *User, filePath string, creds ccacheCredential) {
	name, err := PrincipalToBloodhoundName(creds.ClientPrincipal, creds.ClientRealm)
	if err != nil {
		slog.Debug("emitHasTGTEdge: PrincipalToBloodhoundName failed", "err", err)
		return
	}
	endKind := "User"
	if !strings.Contains(name, "@") {
		endKind = "Computer"
	}
	b.AddEdge("GLH_HasTGT",
		opengraph.ByID("GLH_SSHUser", h.ReferenceUser(owner.UID)),
		opengraph.ByProperty(endKind, opengraph.PropEq("name", name)),
		map[string]any{
			"TicketCacheFile": filePath,
			"StartTime":       creds.StartTime.UTC().Format(time.RFC3339),
			"EndTime":         creds.EndTime.UTC().Format(time.RFC3339),
			"RenewTime":       creds.RenewTill.UTC().Format(time.RFC3339),
		})
}

// findFileTicketCaches returns all on-disk Kerberos ticket caches.
// TODO: add uid parsing.
// TODO: add *.ccache files.
func findFileTicketCaches(ctx context.Context) []string {
	var caches []string
	for _, pattern := range []string{"/tmp/krb5cc*", "/run/user/*/krb5cc/*"} {
		matches, _ := localGlob(ctx, pattern)
		caches = append(caches, matches...)
	}
	return caches
}

// findKeyringTicketCaches finds paths of kernel keyring ticket caches.
// https://github.com/TarlogicSecurity/tickey
// TODO: not yet implemented.
func findKeyringTicketCaches() []string { return nil }

// findKCMTicketCaches finds paths of SSSD Kerberos Cache Manager caches.
// https://github.com/mandiant/SSSDKCMExtractor
// TODO: not yet implemented.
func findKCMTicketCaches() []string {
	kerbCacheManagerDB := "/var/lib/sss/secrets/secrets.ldb"
	if !isPathOnLocalFS(kerbCacheManagerDB) {
		return nil
	}
	if _, err := os.Stat(kerbCacheManagerDB); err == nil {
		slog.Debug("[NOT IMPLEMENTED] Kerberos tickets cannot be extracted: function not implemented", "path", kerbCacheManagerDB)
	}
	return nil
}

// PrincipalToBloodhoundName converts a Kerberos principal + realm into the
// node name expected by BloodHound ingest. It handles user UPNs
// (user@DEMO.LOCAL), machine-account UPNs (machine$@DEMO.LOCAL ->
// machine.DEMO.LOCAL), and HOST/ SPNs (HOST/machine[.realm]@DEMO.LOCAL ->
// machine.DEMO.LOCAL). Any other principal shape returns an error.
func PrincipalToBloodhoundName(principal string, realm string) (string, error) {
	principal = strings.ToUpper(principal)
	realm = strings.ToUpper(realm)
	if principal == "" || realm == "" || strings.HasPrefix(principal, "@") {
		return "", fmt.Errorf("skipping principal: %s@%s", principal, realm)
	}

	if !strings.Contains(principal, "@") {
		principal += "@" + realm
	}

	// UPN: user@demo.local
	if !strings.Contains(principal, "/") && !strings.Contains(principal, "$@") {
		return principal, nil
	}

	// Machine-account UPN: machine$@demo.local -> machine.demo.local
	if !strings.Contains(principal, "/") && strings.Contains(principal, "$@") {
		principal = strings.ReplaceAll(principal, "$@", ".")
		return principal, nil
	}

	// HOST/ SPN: host/machine[.realm]@demo.local -> machine.demo.local
	if principal, found := strings.CutPrefix(principal, "HOST/"); found {
		principal = strings.ReplaceAll(principal, "@"+realm, "")
		if !strings.Contains(principal, ".") {
			principal = fmt.Sprintf("%s.%s", principal, realm)
		}
		return principal, nil
	}
	return "", fmt.Errorf("skipping principal: %s@%s", principal, realm)
}
