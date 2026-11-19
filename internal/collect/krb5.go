package collect

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// MaxKeytabSize caps Kerberos keytab file reads.
	MaxKeytabSize = 32 << 20 // 32 MiB
	// MaxCCacheSize caps Kerberos credential cache file reads.
	MaxCCacheSize = 32 << 20 // 32 MiB
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

// loadKeytab reads and parses filePath within the timeout/cancellation boundary of ctx.
func loadKeytab(ctx context.Context, filePath string) ([]keytabEntry, error) {
	data, err := readFileWithCtx(ctx, filePath, MaxKeytabSize)
	if err != nil {
		return nil, err
	}
	return parseKeytab(data)
}

// loadCCache reads and parses filePath within the timeout/cancellation boundary of ctx.
func loadCCache(ctx context.Context, filePath string) ([]ccacheCredential, error) {
	data, err := readFileWithCtx(ctx, filePath, MaxCCacheSize)
	if err != nil || len(data) == 0 {
		return nil, err
	}
	return parseCCache(data)
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
			return entries, errors.New("truncated keytab entry size")
		}
		size := int32(rawSize)
		if size == 0 {
			break
		}
		if size < 0 {
			if !s.Skip(int(-int64(size))) {
				return entries, errors.New("truncated keytab entry")
			}
			continue
		}
		var er, realm, comp, key cryptobyte.String
		var rawComp uint16
		if !s.ReadBytes((*[]byte)(&er), int(size)) || !er.ReadUint16(&rawComp) {
			return entries, errors.New("truncated keytab entry")
		}
		numComponents := int(int16(rawComp))
		if numComponents < 1 || numComponents > len(er)/2 || !er.ReadUint16LengthPrefixed(&realm) || realm.Empty() {
			return entries, errors.New("invalid keytab principal")
		}
		components := make([]string, numComponents)
		for i := range components {
			if !er.ReadUint16LengthPrefixed(&comp) || comp.Empty() {
				return entries, errors.New("truncated keytab component")
			}
			components[i] = string(comp)
		}
		// Skip name_type (4) + timestamp (4) + vno8 (1) + keytype (2) = 11 bytes, then validate uint16-prefixed key.
		if !er.Skip(11) || !er.ReadUint16LengthPrefixed(&key) || key.Empty() {
			return entries, errors.New("truncated keytab entry")
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
			return creds, errors.New("invalid ccache client principal")
		}
		serverPrincipal, _, ok := readCCachePrincipal(&s)
		if !ok {
			return creds, errors.New("invalid ccache server principal")
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
			return creds, errors.New("truncated ccache credential")
		}
		for range numAddrs {
			if !s.Skip(2) || !skipUint32Prefixed(&s) {
				return creds, errors.New("truncated ccache address")
			}
		}
		if !s.ReadUint32(&numAuthData) {
			return creds, errors.New("truncated ccache authdata count")
		}
		for range numAuthData {
			if !s.Skip(2) || !skipUint32Prefixed(&s) {
				return creds, errors.New("truncated ccache authdata")
			}
		}
		if !skipUint32Prefixed(&s) || !skipUint32Prefixed(&s) {
			return creds, errors.New("truncated ccache ticket")
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
