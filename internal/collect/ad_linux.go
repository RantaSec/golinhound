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
	"golang.org/x/crypto/cryptobyte"
)

// Timeouts for Kerberos artifact discovery and parsing.
const (
	CredentialCacheLoadTimeout = 3 * time.Second
	KeytabFindTimeout          = 5 * time.Second
	KeytabLoadTimeout          = 3 * time.Second
)

// keytabEntry holds the principal and realm parsed from one keytab record.
type keytabEntry struct {
	Principal string
	Realm     string
}

// ccacheCredential holds the principal and lifetime metadata parsed from
// one Kerberos credential cache entry.
type ccacheCredential struct {
	ClientPrincipal string
	ClientRealm     string
	ServerPrincipal string
	StartTime       time.Time
	EndTime         time.Time
	RenewTill       time.Time
}

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

	wg.Go(func() { findKeytabFiles(cctx, chKeytabs, "/etc/", 2) })
	wg.Go(func() { findKeytabFiles(cctx, chKeytabs, "/home/", 1) })

	go func() {
		wg.Wait()
		close(chKeytabs)
	}()

	for file := range chKeytabs {
		ctxLoad, cancelLoad := context.WithTimeout(context.Background(), KeytabLoadTimeout)
		entries, err := loadKeytab(ctxLoad, file)
		cancelLoad()
		if err != nil {
			slog.Error("could not load keytab", "file", file, "err", err)
			continue
		}
		for _, entry := range entries {
			emitHasKeytabEdge(h, b, file, entry.Principal, entry.Realm)
		}
	}
}

// emitHasKeytabEdge emits one HasKeytab edge from the SSHUser that
// owns the keytab file to the principal (resolved to a BloodHound
// node name). The end node kind is User for principals containing
// "@", Computer otherwise. Principals that don't fit a known shape
// (see PrincipalToBloodhoundName) and files whose uid doesn't map to
// any Host.Users entry (see Host.fileOwner) are debug-logged and
// dropped.
func emitHasKeytabEdge(h *Host, b *opengraph.GraphBuilder, filePath, principal, realm string) {
	name, err := PrincipalToBloodhoundName(principal, realm)
	if err != nil {
		slog.Debug("emitHasKeytabEdge: PrincipalToBloodhoundName failed", "err", err)
		return
	}
	owner := h.fileOwner(filePath)
	if owner == nil {
		return
	}
	endKind := "User"
	if !strings.Contains(name, "@") {
		endKind = "Computer"
	}
	b.AddEdge("HasKeytab",
		opengraph.ByID("SSHUser", h.ReferenceUser(owner.UID)),
		opengraph.ByProperty(endKind, opengraph.PropEq("name", name)),
		map[string]any{"KeytabFile": filePath})
}

// findKeytabFiles walks rootDir up to maxDepth levels, sending every
// *.keytab path it finds into chKeytabs. Respects ctx cancellation.
// Per-entry walk errors are silently dropped (the walk continues);
// only a terminal error returned by filepath.WalkDir itself —
// typically ctx cancellation — is logged.
func findKeytabFiles(ctx context.Context, chKeytabs chan<- string, rootDir string, maxDepth int) {
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

// loadKeytab reads and parses filePath inside a goroutine so that
// ctx cancellation can abort a stuck read. This wrapper provides the
// timeout boundary for the entire keytab-load step.
func loadKeytab(ctx context.Context, filePath string) ([]keytabEntry, error) {
	type result struct {
		entries []keytabEntry
		err     error
	}
	resultChan := make(chan result, 1)
	go func() {
		data, err := os.ReadFile(filePath)
		if err != nil {
			resultChan <- result{err: err}
			return
		}
		entries, err := parseKeytab(data)
		resultChan <- result{entries: entries, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.entries, res.err
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
		credsList, err := loadCCache(ctx, cacheFile)
		cancel()
		if err != nil {
			slog.Error("could not load Kerberos ticket cache", "cacheFile", cacheFile, "err", err)
			continue
		}
		for _, creds := range credsList {
			// only true TGTs (krbtgt/...) become HasTGT edges
			if !strings.HasPrefix(creds.ServerPrincipal, "krbtgt/") {
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

// emitHasTGTEdge emits one HasTGT edge from the SSHUser that owns
// the ccache file to the client principal of creds (resolved via
// PrincipalToBloodhoundName). Edge properties carry the ticket's
// StartTime/EndTime/RenewTime in RFC3339. Ccaches whose uid doesn't
// map to any Host.Users entry (see Host.fileOwner) are debug-logged
// and dropped.
func emitHasTGTEdge(h *Host, b *opengraph.GraphBuilder, filePath string, creds ccacheCredential) {
	name, err := PrincipalToBloodhoundName(creds.ClientPrincipal, creds.ClientRealm)
	if err != nil {
		slog.Debug("emitHasTGTEdge: PrincipalToBloodhoundName failed", "err", err)
		return
	}
	owner := h.fileOwner(filePath)
	if owner == nil {
		return
	}
	endKind := "User"
	if !strings.Contains(name, "@") {
		endKind = "Computer"
	}
	b.AddEdge("HasTGT",
		opengraph.ByID("SSHUser", h.ReferenceUser(owner.UID)),
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
func findFileTicketCaches() []string {
	var caches []string
	c1, _ := filepath.Glob("/tmp/krb5cc*")
	caches = append(caches, c1...)
	c2, _ := filepath.Glob("/run/user/*/krb5cc/*")
	caches = append(caches, c2...)
	return caches
}

// loadCCache reads and parses filePath inside a goroutine so that ctx
// cancellation can abort a stuck read. Returns early with "file is empty"
// if os.Stat fails (missing/unreadable) or reports a zero-byte file.
func loadCCache(ctx context.Context, filePath string) ([]ccacheCredential, error) {
	fi, err := os.Stat(filePath)
	if err != nil || fi.Size() == 0 {
		return nil, fmt.Errorf("file is empty: %s", filePath)
	}
	type result struct {
		creds []ccacheCredential
		err   error
	}
	resultChan := make(chan result, 1)
	go func() {
		data, err := os.ReadFile(filePath)
		if err != nil {
			resultChan <- result{err: err}
			return
		}
		creds, err := parseCCache(data)
		resultChan <- result{creds: creds, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.creds, res.err
	}
}

// parseKeytab decodes an MIT Kerberos v2 keytab (0x0502) and returns the
// principal and realm of each entry. Legacy v1 (0x0501) keytabs from early
// 1990s Kerberos used host-native byte order and have been superseded by
// big-endian v2 across MIT Kerberos, Heimdal, SSSD, and Samba/AD; supporting
// only v2 allows parsing directly with cryptobyte's big-endian primitives.
func parseKeytab(b []byte) ([]keytabEntry, error) {
	s := cryptobyte.String(b)
	var version uint16
	if !s.ReadUint16(&version) || version != 0x0502 || len(s) < 4 {
		return nil, errors.New("invalid keytab header")
	}

	var entries []keytabEntry
	for !s.Empty() {
		var rawSize uint32
		if !s.ReadUint32(&rawSize) {
			return nil, errors.New("truncated keytab entry size")
		}
		size := int32(rawSize)
		if size == 0 {
			break
		}
		if size < 0 {
			if !s.Skip(int(-int64(size))) {
				return nil, errors.New("truncated keytab entry")
			}
			continue
		}
		var er, realm, comp, key cryptobyte.String
		var rawComp uint16
		if !s.ReadBytes((*[]byte)(&er), int(size)) || !er.ReadUint16(&rawComp) {
			return nil, errors.New("truncated keytab entry")
		}
		numComponents := int(int16(rawComp))
		if numComponents < 1 || numComponents > len(er)/2 || !er.ReadUint16LengthPrefixed(&realm) || realm.Empty() {
			return nil, errors.New("invalid keytab principal")
		}
		components := make([]string, numComponents)
		for i := range components {
			if !er.ReadUint16LengthPrefixed(&comp) || comp.Empty() {
				return nil, errors.New("truncated keytab component")
			}
			components[i] = string(comp)
		}
		// Skip name_type (4) + timestamp (4) + vno8 (1) + keytype (2) = 11 bytes, then validate uint16-prefixed key.
		if !er.Skip(11) || !er.ReadUint16LengthPrefixed(&key) || key.Empty() {
			return nil, errors.New("truncated keytab entry")
		}
		entries = append(entries, keytabEntry{
			Principal: strings.Join(components, "/") + "@" + string(realm),
			Realm:     string(realm),
		})
	}
	return entries, nil
}

// parseCCache decodes an MIT Kerberos v3 or v4 credential cache (0x0503 or
// 0x0504). Legacy v1/v2 (0x0501/0x0502) caches used host-native byte order
// and have been obsolete since Kerberos 5 (1999); supporting only big-endian
// v3/v4 allows parsing directly with cryptobyte's big-endian primitives.
func parseCCache(b []byte) ([]ccacheCredential, error) {
	s := cryptobyte.String(b)
	var version uint16
	if !s.ReadUint16(&version) || (version != 0x0503 && version != 0x0504) {
		return nil, errors.New("invalid ccache header")
	}

	if version == 0x0504 {
		var hdr, val cryptobyte.String
		var tag uint16
		if !s.ReadUint16LengthPrefixed(&hdr) {
			return nil, errors.New("truncated ccache header")
		}
		for !hdr.Empty() {
			if !hdr.ReadUint16(&tag) || !hdr.ReadUint16LengthPrefixed(&val) {
				return nil, errors.New("invalid ccache header tag")
			}
		}
	}

	if _, _, ok := readCCachePrincipal(&s); !ok {
		return nil, errors.New("invalid ccache default principal")
	}

	var creds []ccacheCredential
	for !s.Empty() {
		clientPrincipal, clientRealm, ok := readCCachePrincipal(&s)
		if !ok {
			return nil, errors.New("invalid ccache client principal")
		}
		serverPrincipal, _, ok := readCCachePrincipal(&s)
		if !ok {
			return nil, errors.New("invalid ccache server principal")
		}
		keyHdr := 2
		if version == 0x0503 {
			keyHdr = 4
		}
		var authTime, startTime, endTime, renewTill, numAddrs, numAuthData uint32
		if !s.Skip(keyHdr) || !skipUint32Prefixed(&s) ||
			!s.ReadUint32(&authTime) || !s.ReadUint32(&startTime) ||
			!s.ReadUint32(&endTime) || !s.ReadUint32(&renewTill) ||
			!s.Skip(5) || !s.ReadUint32(&numAddrs) {
			return nil, errors.New("truncated ccache credential")
		}
		for range numAddrs {
			if !s.Skip(2) || !skipUint32Prefixed(&s) {
				return nil, errors.New("truncated ccache address")
			}
		}
		if !s.ReadUint32(&numAuthData) {
			return nil, errors.New("truncated ccache authdata count")
		}
		for range numAuthData {
			if !s.Skip(2) || !skipUint32Prefixed(&s) {
				return nil, errors.New("truncated ccache authdata")
			}
		}
		if !skipUint32Prefixed(&s) || !skipUint32Prefixed(&s) {
			return nil, errors.New("truncated ccache ticket")
		}
		creds = append(creds, ccacheCredential{
			ClientPrincipal: clientPrincipal,
			ClientRealm:     clientRealm,
			ServerPrincipal: serverPrincipal,
			StartTime:       time.Unix(int64(int32(startTime)), 0),
			EndTime:         time.Unix(int64(int32(endTime)), 0),
			RenewTill:       time.Unix(int64(int32(renewTill)), 0),
		})
	}
	return creds, nil
}

func readCCachePrincipal(s *cryptobyte.String) (string, string, bool) {
	var rawComp uint32
	if !s.Skip(4) || !s.ReadUint32(&rawComp) {
		return "", "", false
	}
	numComponents := int(int32(rawComp))
	var realm string
	if numComponents < 1 || numComponents > len(*s)/4 || !readUint32String(s, &realm) || realm == "" {
		return "", "", false
	}
	components := make([]string, numComponents)
	for i := range components {
		if !readUint32String(s, &components[i]) || components[i] == "" {
			return "", "", false
		}
	}
	return strings.Join(components, "/"), realm, true
}

func readUint32String(s *cryptobyte.String, out *string) bool {
	var n uint32
	var b []byte
	if !s.ReadUint32(&n) || !s.ReadBytes(&b, int(n)) {
		return false
	}
	*out = string(b)
	return true
}

func skipUint32Prefixed(s *cryptobyte.String) bool {
	var n uint32
	return s.ReadUint32(&n) && s.Skip(int(n))
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
