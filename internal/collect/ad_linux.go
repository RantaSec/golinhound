package collect

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
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
	emitKeytabs(ctx, h, b)
	emitTGTs(h, b)
	// Not yet implemented; left here for visibility.
	findKCMTicketCaches()
	findKeyringTicketCaches()
	return nil
}

// emitKeytabs walks /etc/ (depth 2) and /home/ (depth 1) in parallel for
// *.keytab files, loads each, and emits one HasKeytab edge per principal
// entry. The find walk is bounded by KeytabFindTimeout; each load has an
// independent KeytabLoadTimeout so a slow/stuck file doesn't impact the
// rest.
func emitKeytabs(ctx context.Context, h *Host, b *opengraph.GraphBuilder) {
	cctx, cancel := context.WithTimeout(ctx, KeytabFindTimeout)
	defer cancel()

	var wg sync.WaitGroup
	chKeytabs := make(chan string)

	wg.Add(2)
	go findKeytabFiles(cctx, &wg, chKeytabs, "/etc/", 2)
	go findKeytabFiles(cctx, &wg, chKeytabs, "/home/", 1)

	go func() {
		wg.Wait()
		close(chKeytabs)
	}()

	for file := range chKeytabs {
		ctxLoad, cancelLoad := context.WithTimeout(context.Background(), KeytabLoadTimeout)
		kt, err := loadKeytab(ctxLoad, file)
		cancelLoad()
		if err != nil {
			slog.Error("could not load keytab", "file", file, "err", err)
			continue
		}
		for _, entry := range kt.Entries {
			emitHasKeytabEdge(h, b, file, entry.Principal.String(), entry.Principal.Realm)
		}
	}
}

// emitHasKeytabEdge emits one HasKeytab edge from the local SSHComputer
// to the principal (resolved to a BloodHound node name). The end node
// kind is User for principals containing "@", Computer otherwise.
// Principals that don't fit a known shape (see PrincipalToBloodhoundName)
// are debug-logged and dropped.
func emitHasKeytabEdge(h *Host, b *opengraph.GraphBuilder, filePath, principal, realm string) {
	name, err := PrincipalToBloodhoundName(principal, realm)
	if err != nil {
		slog.Debug("emitHasKeytabEdge: PrincipalToBloodhoundName failed", "err", err)
		return
	}
	endKind := "User"
	if !strings.Contains(name, "@") {
		endKind = "Computer"
	}
	b.AddEdge("HasKeytab",
		opengraph.ByID("SSHComputer", h.ComputerID()),
		opengraph.ByProperty(endKind, opengraph.PropEq("name", name)),
		map[string]any{"FilePath": filePath})
}

// findKeytabFiles walks rootDir up to maxDepth levels, sending every
// *.keytab path it finds into chKeytabs. Respects ctx cancellation and
// always calls wg.Done() on return. Per-entry walk errors are silently
// dropped (the walk continues); only a terminal error returned by
// filepath.WalkDir itself — typically ctx cancellation — is logged.
func findKeytabFiles(ctx context.Context, wg *sync.WaitGroup, chKeytabs chan<- string, rootDir string, maxDepth int) {
	defer wg.Done()
	rootDir = filepath.Clean(rootDir)
	rootDepth := strings.Count(rootDir, string(os.PathSeparator))

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		currDepth := strings.Count(path, string(os.PathSeparator)) - rootDepth
		if currDepth > maxDepth && d.IsDir() {
			return filepath.SkipDir
		}
		if !d.IsDir() && filepath.Ext(d.Name()) == ".keytab" {
			chKeytabs <- path
		}
		return nil
	})
	if err != nil {
		slog.Error("WalkDir failed", "root", rootDir, "maxDepth", maxDepth, "err", err)
	}
}

// loadKeytab calls keytab.Load on filePath inside a goroutine so that
// ctx cancellation can abort a stuck parse. The library call itself
// has no context support; this wrapper provides the timeout boundary
// for the entire keytab-load step.
func loadKeytab(ctx context.Context, filePath string) (*keytab.Keytab, error) {
	type result struct {
		keytab *keytab.Keytab
		err    error
	}
	resultChan := make(chan result, 1)
	go func() {
		kt, err := keytab.Load(filePath)
		resultChan <- result{keytab: kt, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.keytab, res.err
	}
}

// emitTGTs iterates every on-disk ticket cache (findFileTicketCaches),
// loads it, and emits one HasTGT edge per Ticket Granting Ticket that
// has not yet expired beyond its renewal window.
func emitTGTs(h *Host, b *opengraph.GraphBuilder) {
	for _, cacheFile := range findFileTicketCaches() {
		fi, err := os.Stat(cacheFile)
		if err != nil || fi.Size() == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), CredentialCacheLoadTimeout)
		ccache, err := loadCCache(ctx, cacheFile)
		cancel()
		if err != nil {
			slog.Error("could not load Kerberos ticket cache", "cacheFile", cacheFile, "err", err)
			continue
		}
		for _, creds := range ccache.Credentials {
			// only true TGTs (krbtgt/...) become HasTGT edges
			if !strings.HasPrefix(creds.Server.PrincipalName.PrincipalNameString(), "krbtgt/") {
				continue
			}
			// expired AND non-renewable: drop
			if now := time.Now(); now.After(creds.EndTime) && now.After(creds.RenewTill) {
				continue
			}
			emitHasTGTEdge(h, b, cacheFile, creds)
		}
	}
}

// emitHasTGTEdge emits one HasTGT edge from the local SSHComputer to
// the client principal of creds (resolved via PrincipalToBloodhoundName).
// Edge properties carry the ticket's StartTime/EndTime/RenewTime in
// RFC3339.
func emitHasTGTEdge(h *Host, b *opengraph.GraphBuilder, filePath string, creds *credentials.Credential) {
	principal := creds.Client.PrincipalName.PrincipalNameString()
	realm := creds.Client.Realm
	name, err := PrincipalToBloodhoundName(principal, realm)
	if err != nil {
		slog.Debug("emitHasTGTEdge: PrincipalToBloodhoundName failed", "err", err)
		return
	}
	endKind := "User"
	if !strings.Contains(name, "@") {
		endKind = "Computer"
	}
	b.AddEdge("HasTGT",
		opengraph.ByID("SSHComputer", h.ComputerID()),
		opengraph.ByProperty(endKind, opengraph.PropEq("name", name)),
		map[string]any{
			"FilePath":  filePath,
			"StartTime": creds.StartTime.UTC().Format(time.RFC3339),
			"EndTime":   creds.EndTime.UTC().Format(time.RFC3339),
			"RenewTime": creds.RenewTill.UTC().Format(time.RFC3339),
		})
}

// findFileTicketCaches returns all on-disk Kerberos ticket caches.
// TODO: add uid parsing.
// TODO: add *.ccache files.
func findFileTicketCaches() []string {
	var caches []string
	c1, _ := filepath.Glob("/tmp/krb5cc*")
	caches = append(caches, c1...)
	c2, _ := filepath.Glob("/run/user/*/krb5cc/*")
	caches = append(caches, c2...)
	return caches
}

// loadCCache calls credentials.LoadCCache on filePath inside a goroutine
// so that ctx cancellation can abort a stuck parse. Returns early with
// "file is empty" if os.Stat fails (missing/unreadable) or reports a
// zero-byte file, so the gokrb5 loader is never handed an unusable input.
func loadCCache(ctx context.Context, filePath string) (*credentials.CCache, error) {
	fi, err := os.Stat(filePath)
	if err != nil || fi.Size() == 0 {
		return nil, fmt.Errorf("file is empty: %s", filePath)
	}
	type result struct {
		ccache *credentials.CCache
		err    error
	}
	resultChan := make(chan result, 1)
	go func() {
		ccache, err := credentials.LoadCCache(filePath)
		resultChan <- result{ccache: ccache, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.ccache, res.err
	}
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
