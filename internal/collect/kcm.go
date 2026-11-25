package collect

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	// DefaultKCMSecretsDB is the default path to SSSD's KCM secrets database.
	DefaultKCMSecretsDB = "/var/lib/sss/secrets/secrets.ldb"
	// MaxKCMSecretsDBSize caps SSSD secrets.ldb reads.
	MaxKCMSecretsDBSize = 192 << 20 // 192 MiB

	tdbMagicFood        = "TDB file\n"
	tdbVersion          = 0x2601196d
	tdbFeatureFlagMagic = 0x0bad1a52
	tdbFeatureFlagMutex = 1 << 0
	tdbRecMagic         = 0x26011999
	tdbDeadMagic        = 0xFEE1DEAD
	tdbHashTableOffset  = 168 + 4 // 168-byte TDB header + 4-byte freelist head
	tdbRecordHdrSize    = 24

	ldbPackFormatV1 = 0x26011967 // DN-indexed LDB (always used by SSSD secrets.ldb)
	kcmCredUUIDSize = 16
)

// errUnsupportedKCMFormat is returned when a KCM ccache record uses a legacy
// SSSD < 2.4.1 format (type=simple JSON or enctype=masterkey) or an
// unrecognized LDB/ccache payload format.
var errUnsupportedKCMFormat = errors.New("unsupported SSSD KCM format")

// kcmCCache groups the credentials parsed from one SSSD KCM ccache record
// together with its owning Linux UID (from cn=<uid>,cn=persistent,cn=kcm).
type kcmCCache struct {
	UID   string
	Creds []ccacheCredential
}

// loadKCMSecretsDB reads and parses an SSSD >= 2.4.1 secrets.ldb file within
// the timeout/cancellation boundary of ctx.
func loadKCMSecretsDB(ctx context.Context, filePath string) ([]kcmCCache, error) {
	data, err := readFileWithCtx(ctx, filePath, MaxKCMSecretsDBSize)
	if err != nil {
		return nil, err
	}
	return parseKCMSecretsDB(data)
}

// parseKCMSecretsDB decodes an SSSD >= 2.4.1 secrets.ldb (LDB v1 over Samba
// TDB) and returns non-secret credential metadata for every KCM ccache entry.
//
// Containers, cn=default pointers, @BASEINFO, and non-KCM hives (cn=secrets)
// are ignored. Per-record errors (such as a stale legacy < 2.4.1 entry on an
// upgraded host or a mid-write corrupt record) are recorded without aborting
// the walk so valid caches for other users are still returned alongside the
// error. If any record failed with errUnsupportedKCMFormat, the returned error
// wraps errUnsupportedKCMFormat.
func parseKCMSecretsDB(data []byte) ([]kcmCCache, error) {
	var (
		caches         []kcmCCache
		firstErr       error
		unsupportedErr error
		errCount       int
	)
	recordErr := func(err error) {
		errCount++
		if firstErr == nil {
			firstErr = err
		}
		if unsupportedErr == nil && errors.Is(err, errUnsupportedKCMFormat) {
			unsupportedErr = err
		}
	}

	err := walkTDB(data, func(key, val []byte) error {
		// LDB stores DN-indexed entries under uppercase TDB keys:
		//   "DN=CN=<UUID>-<NAME>,CN=CCACHE,CN=<UID>,CN=PERSISTENT,CN=KCM\x00"
		uid, ok := extractUIDFromTDBKey(key)
		if !ok {
			return nil
		}

		secret, err := unpackKCMRecordV1(val)
		if err != nil {
			recordErr(fmt.Errorf("record %q: %w", bytes.TrimRight(key, "\x00"), err))
			return nil
		}
		if len(secret) == 0 {
			return nil
		}

		creds, err := parseKCMBinaryPayload(secret)
		if err != nil {
			recordErr(fmt.Errorf("record %q: %w", bytes.TrimRight(key, "\x00"), err))
			return nil
		}
		if len(creds) > 0 {
			caches = append(caches, kcmCCache{UID: uid, Creds: creds})
		}
		return nil
	})
	if err != nil {
		recordErr(err)
	}
	if errCount == 0 {
		return caches, nil
	}
	rep := firstErr
	if unsupportedErr != nil {
		rep = unsupportedErr
	}
	if errCount > 1 {
		return caches, fmt.Errorf("%w (and %d more KCM record error(s))", rep, errCount-1)
	}
	return caches, rep
}

// extractUIDFromTDBKey matches TDB keys of the form
// "DN=CN=<uuid>-<name>,CN=CCACHE,CN=<uid>,CN=PERSISTENT,CN=KCM" (with optional
// trailing NUL) and returns the canonical decimal Linux owner UID.
func extractUIDFromTDBKey(key []byte) (string, bool) {
	s := strings.ToUpper(string(bytes.TrimRight(key, "\x00")))
	body, ok := strings.CutPrefix(s, "DN=")
	if !ok {
		return "", false
	}
	body, ok = strings.CutSuffix(body, ",CN=PERSISTENT,CN=KCM")
	if !ok {
		return "", false
	}
	if !strings.HasPrefix(body, "CN=") {
		return "", false
	}
	// Find the first unescaped comma ending the leaf RDN (CN=<uuid>-<name>),
	// respecting RFC 4514 / LDB backslash escapes (e.g. \, or \\).
	commaIdx := -1
	for i := len("CN="); i < len(body); i++ {
		if body[i] == '\\' {
			i++ // skip escaped character
			continue
		}
		if body[i] == ',' {
			commaIdx = i
			break
		}
	}
	if commaIdx <= len("CN=") {
		return "", false
	}
	uidStr, ok := strings.CutPrefix(body[commaIdx+1:], "CN=CCACHE,CN=")
	if !ok || strings.ContainsRune(uidStr, ',') {
		return "", false
	}
	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(uid, 10), true
}

// walkTDB visits every live record in a Samba TDB buffer by traversing its
// hash buckets (ignoring freelist, dead, and recovery records).
func walkTDB(buf []byte, fn func(key, val []byte) error) error {
	if len(buf) < tdbHashTableOffset {
		return fmt.Errorf("tdb: %w", io.ErrUnexpectedEOF)
	}
	if !bytes.HasPrefix(buf, []byte(tdbMagicFood)) {
		return errors.New("tdb: invalid magic header")
	}

	var bo binary.ByteOrder
	switch v := binary.LittleEndian.Uint32(buf[32:36]); {
	case v == tdbVersion:
		bo = binary.LittleEndian
	case binary.BigEndian.Uint32(buf[32:36]) == tdbVersion:
		bo = binary.BigEndian
	default:
		return fmt.Errorf("tdb: unsupported version 0x%08x", v)
	}

	if bo.Uint32(buf[40:44]) == tdbFeatureFlagMagic && bo.Uint32(buf[60:64])&tdbFeatureFlagMutex != 0 {
		return fmt.Errorf("%w: TDB mutex locking is not supported", errUnsupportedKCMFormat)
	}

	hashSize := bo.Uint32(buf[36:40])
	dataStart := uint64(tdbHashTableOffset) + uint64(hashSize)*4
	if dataStart > uint64(len(buf)) {
		return fmt.Errorf("tdb: hash table: %w", io.ErrUnexpectedEOF)
	}

	seen := make(map[uint32]bool)
	for i := range hashSize {
		off := tdbHashTableOffset + int(i)*4
		for recOff := bo.Uint32(buf[off : off+4]); recOff != 0; {
			if seen[recOff] {
				return fmt.Errorf("tdb: cycle at 0x%x", recOff)
			}
			seen[recOff] = true

			if uint64(recOff) < dataStart || uint64(recOff)+tdbRecordHdrSize > uint64(len(buf)) {
				return fmt.Errorf("tdb: record offset 0x%x out of bounds", recOff)
			}
			hdr := buf[recOff : recOff+tdbRecordHdrSize]
			next, recLen := bo.Uint32(hdr[0:4]), bo.Uint32(hdr[4:8])
			keyLen, dataLen := bo.Uint32(hdr[8:12]), bo.Uint32(hdr[12:16])
			magic := bo.Uint32(hdr[20:24])
			if magic == tdbDeadMagic {
				recOff = next
				continue
			}
			if magic != tdbRecMagic || uint64(keyLen)+uint64(dataLen) > uint64(recLen) {
				return fmt.Errorf("tdb: corrupt record at 0x%x", recOff)
			}

			keyStart := uint64(recOff) + tdbRecordHdrSize
			keyEnd := keyStart + uint64(keyLen)
			dataEnd := keyEnd + uint64(dataLen)
			if dataEnd > uint64(len(buf)) {
				return fmt.Errorf("tdb: payload at 0x%x: %w", recOff, io.ErrUnexpectedEOF)
			}
			if err := fn(buf[keyStart:keyEnd], buf[keyEnd:dataEnd]); err != nil {
				return err
			}
			recOff = next
		}
	}
	return nil
}

// unpackKCMRecordV1 unpacks a Samba LDB v1 record (0x26011967), enforces SSSD
// >= 2.4.1 type/enctype guards, and returns the raw "secret" attribute value.
func unpackKCMRecordV1(data []byte) ([]byte, error) {
	c := &kcmCursor{buf: data, bo: binary.LittleEndian}
	if ver := c.u32(); c.err == nil && ver != ldbPackFormatV1 {
		return nil, fmt.Errorf("%w: LDB pack format 0x%08x", errUnsupportedKCMFormat, ver)
	}
	numElements := c.u32()
	_ = c.cstring() // linearized DN
	if c.err != nil {
		return nil, c.err
	}
	if uint64(numElements) > uint64(len(c.buf))/6 {
		return nil, io.ErrUnexpectedEOF
	}

	var secret []byte
	for range numElements {
		name := c.cstring()
		numVals := c.u32()
		if c.err != nil {
			return nil, c.err
		}
		if name == "" {
			return nil, errors.New("ldb: empty attribute name")
		}
		if uint64(numVals) > uint64(len(c.buf))/5 {
			return nil, io.ErrUnexpectedEOF
		}
		for j := range numVals {
			val := c.varlen()
			pad := c.u8() // trailing NUL pad
			if c.err != nil {
				return nil, c.err
			}
			if pad != 0 {
				return nil, fmt.Errorf("ldb: non-NUL value pad 0x%02x for attribute %q", pad, name)
			}
			if j != 0 {
				continue
			}
			switch strings.ToLower(name) {
			case "type":
				t := string(bytes.TrimRight(val, "\x00"))
				if strings.EqualFold(t, "container") {
					return nil, nil
				}
				if t != "" && !strings.EqualFold(t, "binary") {
					return nil, fmt.Errorf("%w: type=%q", errUnsupportedKCMFormat, t)
				}
			case "enctype":
				if enc := string(bytes.TrimRight(val, "\x00")); enc != "" && !strings.EqualFold(enc, "plaintext") {
					return nil, fmt.Errorf("%w: enctype=%q", errUnsupportedKCMFormat, enc)
				}
			case "secret":
				secret = val
			}
		}
	}
	return secret, c.err
}

// parseKCMBinaryPayload decodes an SSSD >= 2.4.1 KCM binary ccache payload
// (sssd src/responder/kcm/kcmsrv_ccache_binary.c). Outer envelope fields use
// host-native endianness; each embedded cred_blob is decoded with krb5.go's
// MIT v4 (0x0504) big-endian credential parser.
func parseKCMBinaryPayload(payload []byte) ([]ccacheCredential, error) {
	c := &kcmCursor{buf: payload, bo: binary.NativeEndian}
	c.skip(4) // int32 kdc_offset

	present := c.u8()
	if c.err != nil {
		return nil, c.err
	}
	if present > 1 {
		return nil, fmt.Errorf("%w: invalid principal presence byte 0x%02x", errUnsupportedKCMFormat, present)
	}
	if present == 1 {
		c.skipVarlen() // realm
		c.skip(4)      // int32 name_type
		compCount := c.u32()
		if c.err != nil {
			return nil, c.err
		}
		if uint64(compCount) > uint64(len(c.buf))/4 {
			return nil, io.ErrUnexpectedEOF
		}
		for range compCount {
			c.skipVarlen()
			if c.err != nil {
				return nil, c.err
			}
		}
	}

	credCount := c.u32()
	if c.err != nil {
		return nil, c.err
	}
	// Each credential requires at least 16-byte UUID + 4-byte blob length.
	if uint64(credCount) > uint64(len(c.buf))/(kcmCredUUIDSize+4) {
		return nil, io.ErrUnexpectedEOF
	}

	creds := make([]ccacheCredential, 0, credCount)
	for range credCount {
		c.skip(kcmCredUUIDSize)
		credBlob := c.varlen()
		if c.err != nil {
			return nil, c.err
		}
		cs := cryptobyte.String(credBlob)
		cred, err := parseCCacheCred(&cs, 0x0504)
		if err != nil {
			return nil, err
		}
		if !cs.Empty() {
			return nil, fmt.Errorf("%w: %d unexpected trailing bytes in cred_blob", errUnsupportedKCMFormat, len(cs))
		}
		creds = append(creds, cred)
	}
	// Trailing bytes after the last credential are expected and intentionally
	// ignored: SSSD's sec_put()/sec_update() (kcmsrv_ccache_secdb.c) writes
	// sss_iobuf_get_size(buf) — the power-of-two-doubled allocation capacity
	// from ensure_bytes() — rather than sss_iobuf_get_len(buf), leaving
	// uninitialized heap slack at the end of every real KCM secret blob.
	return creds, nil
}

// kcmCursor is a sticky-error binary reader for host-endian/little-endian
// LDB and KCM envelope fields (where cryptobyte's big-endian primitives do not apply).
type kcmCursor struct {
	buf []byte
	bo  binary.ByteOrder
	err error
}

func (c *kcmCursor) take(n uint32) []byte {
	if c.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(c.buf)) {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	b := c.buf[:n]
	c.buf = c.buf[n:]
	return b
}

func (c *kcmCursor) skip(n uint32)  { _ = c.take(n) }
func (c *kcmCursor) varlen() []byte { return c.take(c.u32()) }
func (c *kcmCursor) skipVarlen()    { c.skip(c.u32()) }

func (c *kcmCursor) u8() uint8 {
	if b := c.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (c *kcmCursor) u32() uint32 {
	if b := c.take(4); b != nil {
		return c.bo.Uint32(b)
	}
	return 0
}

func (c *kcmCursor) cstring() string {
	if c.err != nil {
		return ""
	}
	i := bytes.IndexByte(c.buf, 0)
	if i < 0 {
		c.err = io.ErrUnexpectedEOF
		return ""
	}
	s := string(c.buf[:i])
	c.buf = c.buf[i+1:]
	return s
}
