package collect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// buildKCMBinaryCCache serializes a ccache according to SSSD's
// src/responder/kcm/kcmsrv_ccache_binary.c:kcm_ccache_to_sec_input_binary.
func buildKCMBinaryCCache(kdcOffset int32, hasClientPrinc bool, clientRealm string, clientComps []string, credBlobs [][]byte) []byte {
	var b bytes.Buffer
	writeVarlen := func(v []byte) {
		_ = binary.Write(&b, binary.NativeEndian, uint32(len(v)))
		b.Write(v)
	}

	_ = binary.Write(&b, binary.NativeEndian, kdcOffset)
	if !hasClientPrinc {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
		writeVarlen([]byte(clientRealm))
		_ = binary.Write(&b, binary.NativeEndian, int32(1))
		_ = binary.Write(&b, binary.NativeEndian, int32(len(clientComps)))
		for _, comp := range clientComps {
			writeVarlen([]byte(comp))
		}
	}

	_ = binary.Write(&b, binary.NativeEndian, uint32(len(credBlobs)))
	for i, blob := range credBlobs {
		var uuid [16]byte
		uuid[0] = byte(i + 1)
		b.Write(uuid[:])
		writeVarlen(blob)
	}
	return b.Bytes()
}

type testLDBAttr struct {
	name string
	vals [][]byte
}

// buildLDBRecordV1 serializes a Samba LDB v1 record (LDB_PACKING_FORMAT = 0x26011967).
func buildLDBRecordV1(dn string, attrs []testLDBAttr) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(ldbPackFormatV1))
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(attrs)))
	b.WriteString(dn)
	b.WriteByte(0)
	for _, a := range attrs {
		b.WriteString(a.name)
		b.WriteByte(0)
		_ = binary.Write(&b, binary.LittleEndian, uint32(len(a.vals)))
		for _, v := range a.vals {
			_ = binary.Write(&b, binary.LittleEndian, uint32(len(v)))
			b.Write(v)
			b.WriteByte(0) // NUL pad
		}
	}
	return b.Bytes()
}

type testTDBEntry struct {
	key  []byte
	data []byte
}

// buildTDB serializes a minimal Samba TDB file with the given byte order and records.
func buildTDB(bo binary.ByteOrder, entries []testTDBEntry) []byte {
	const hashSize = uint32(16)
	header := make([]byte, tdbHashTableOffset+hashSize*4)
	copy(header[:len(tdbMagicFood)], tdbMagicFood)
	bo.PutUint32(header[32:36], tdbVersion)
	bo.PutUint32(header[36:40], hashSize)

	var body bytes.Buffer
	baseOff := uint32(len(header))

	// Put all records into hash bucket 0 as a linked chain so traversal
	// exercises both empty buckets and multi-record hash chains.
	var headOff uint32
	for _, e := range entries {
		recOff := baseOff + uint32(body.Len())
		payloadLen := uint32(len(e.key) + len(e.data))
		recLen := payloadLen + 4 // space for tailer
		var hdr [tdbRecordHdrSize]byte
		bo.PutUint32(hdr[0:4], headOff) // next
		bo.PutUint32(hdr[4:8], recLen)
		bo.PutUint32(hdr[8:12], uint32(len(e.key)))
		bo.PutUint32(hdr[12:16], uint32(len(e.data)))
		bo.PutUint32(hdr[16:20], 0) // full_hash (unused by walker)
		bo.PutUint32(hdr[20:24], tdbRecMagic)
		body.Write(hdr[:])
		body.Write(e.key)
		body.Write(e.data)
		var tailer [4]byte
		bo.PutUint32(tailer[:], tdbRecordHdrSize+recLen)
		body.Write(tailer[:])
		headOff = recOff
	}
	bo.PutUint32(header[tdbHashTableOffset:tdbHashTableOffset+4], headOff)

	return append(header, body.Bytes()...)
}

func writeTestLDBWithLdbadd(t *testing.T, ldif string) string {
	t.Helper()
	if _, err := exec.LookPath("ldbadd"); err != nil {
		t.Skip("ldbadd not installed; skipping real libldb integration test")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.ldb")
	ldifPath := filepath.Join(dir, "seed.ldif")
	if err := os.WriteFile(ldifPath, []byte(ldif), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ldbadd", "-H", dbPath, ldifPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ldbadd failed: %v\n%s", err, out)
	}
	return dbPath
}

func TestParseKCMSecretsDBSynthetic(t *testing.T) {
	now := uint32(1700000000)
	tgtAlice := buildCCacheCred(0x0504, testCCacheCredSpec{
		client:    buildCCachePrinc(1, "EXAMPLE.COM", "alice"),
		server:    buildCCachePrinc(2, "EXAMPLE.COM", "krbtgt", "EXAMPLE.COM"),
		enctype:   18,
		key:       bytes.Repeat([]byte{0xAA}, 32),
		authTime:  now,
		startTime: now,
		endTime:   now + 36000,
		renewTill: now + 604800,
		ticket:    []byte("tgt-bytes"),
	})
	svcAlice := buildCCacheCred(0x0504, testCCacheCredSpec{
		client:    buildCCachePrinc(1, "EXAMPLE.COM", "alice"),
		server:    buildCCachePrinc(2, "EXAMPLE.COM", "HTTP", "web.example.com"),
		enctype:   18,
		key:       bytes.Repeat([]byte{0xBB}, 32),
		authTime:  now + 60,
		startTime: now + 60,
		endTime:   now + 36000,
		ticket:    []byte("st-bytes"),
	})
	confEntry := buildCCacheCred(0x0504, testCCacheCredSpec{
		client: buildCCachePrinc(1, "EXAMPLE.COM", "alice"),
		server: buildCCachePrinc(0, "X-CACHECONF:", "krb5_ccache_conf_data", "fast_avail"),
		ticket: []byte("yes"),
	})

	cc26 := buildKCMBinaryCCache(0, true, "EXAMPLE.COM", []string{"alice"}, [][]byte{tgtAlice, svcAlice, confEntry})
	ccNullPrinc := buildKCMBinaryCCache(-12, false, "", nil, [][]byte{mitMarshalV4Cred1})

	entries := []testTDBEntry{
		{
			key:  []byte("DN=@BASEINFO\x00"),
			data: buildLDBRecordV1("@BASEINFO", []testLDBAttr{{name: "sequenceNumber", vals: [][]byte{[]byte("4")}}}),
		},
		{
			key:  []byte("DN=CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{{name: "type", vals: [][]byte{[]byte("container")}}}),
		},
		{
			key:  []byte("DN=CN=DEFAULT,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=default,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{[]byte("11111111-2222-3333-4444-555555555555")}}}),
		},
		{
			// Unrelated cn=secrets hive (even encrypted) must be ignored.
			key: []byte("DN=CN=APP,CN=1000,CN=USERS,CN=SECRETS\x00"),
			data: buildLDBRecordV1("cn=app,cn=1000,cn=users,cn=secrets", []testLDBAttr{
				{name: "type", vals: [][]byte{[]byte("simple")}},
				{name: "enctype", vals: [][]byte{[]byte("masterkey")}},
				{name: "secret", vals: [][]byte{[]byte("ZW5jcnlwdGVk")}},
			}),
		},
		{
			// SSSD >= 2.6.0 record (no type/enctype attributes).
			key: []byte("DN=CN=11111111-2222-3333-4444-555555555555-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=11111111-2222-3333-4444-555555555555-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{
				{name: "secret", vals: [][]byte{cc26}},
				{name: "creationTime", vals: [][]byte{[]byte("1700000000")}},
			}),
		},
		{
			// SSSD 2.4.1-2.5.x record (type=binary, enctype=plaintext) with NULL cache principal.
			key: []byte("DN=CN=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE-2000,CN=CCACHE,CN=2000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee-2000,cn=ccache,cn=2000,cn=persistent,cn=kcm", []testLDBAttr{
				{name: "type", vals: [][]byte{[]byte("binary")}},
				{name: "enctype", vals: [][]byte{[]byte("plaintext")}},
				{name: "secret", vals: [][]byte{ccNullPrinc}},
				{name: "creationTime", vals: [][]byte{[]byte("1700000000")}},
			}),
		},
	}

	for _, tc := range []struct {
		name string
		bo   binary.ByteOrder
	}{
		{"little_endian_tdb", binary.LittleEndian},
		{"big_endian_tdb", binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildTDB(tc.bo, entries)
			caches, err := parseKCMSecretsDB(raw)
			if err != nil {
				t.Fatalf("parseKCMSecretsDB() unexpected error: %v", err)
			}
			byUID := make(map[string][]ccacheCredential, len(caches))
			for _, cc := range caches {
				byUID[cc.UID] = append(byUID[cc.UID], cc.Creds...)
			}
			if len(byUID["1000"]) != 3 {
				t.Fatalf("uid 1000 creds = %d, want 3: %+v", len(byUID["1000"]), byUID["1000"])
			}
			if got := byUID["1000"][0]; got.ClientPrincipal != "alice" ||
				got.ClientRealm != "EXAMPLE.COM" ||
				got.ServerPrincipal != "krbtgt/EXAMPLE.COM" ||
				!got.StartTime.Equal(time.Unix(int64(now), 0)) ||
				!got.EndTime.Equal(time.Unix(int64(now+36000), 0)) ||
				!got.RenewTill.Equal(time.Unix(int64(now+604800), 0)) {
				t.Fatalf("uid 1000 cred[0] = %+v", got)
			}
			if len(byUID["2000"]) != 1 || byUID["2000"][0].ClientPrincipal != "testclient" || byUID["2000"][0].ServerPrincipal != "test/host" {
				t.Fatalf("uid 2000 creds = %+v", byUID["2000"])
			}
		})
	}
}

func TestParseKCMSecretsDBRealLibLDB(t *testing.T) {
	now := uint32(1700000000)
	tgtAlice := buildCCacheCred(0x0504, testCCacheCredSpec{
		client:    buildCCachePrinc(1, "EXAMPLE.COM", "alice"),
		server:    buildCCachePrinc(2, "EXAMPLE.COM", "krbtgt", "EXAMPLE.COM"),
		enctype:   18,
		key:       bytes.Repeat([]byte{0x11}, 32),
		authTime:  now,
		startTime: now,
		endTime:   now + 3600,
		renewTill: now + 86400,
		ticket:    []byte("tgt"),
	})
	tgtBob := buildCCacheCred(0x0504, testCCacheCredSpec{
		client:    buildCCachePrinc(1, "EXAMPLE.COM", "bob"),
		server:    buildCCachePrinc(2, "EXAMPLE.COM", "krbtgt", "EXAMPLE.COM"),
		enctype:   18,
		key:       bytes.Repeat([]byte{0x22}, 32),
		authTime:  now,
		startTime: now,
		endTime:   now + 3600,
		renewTill: now + 86400,
		ticket:    []byte("tgt-bob"),
	})
	ccAlice := buildKCMBinaryCCache(0, true, "EXAMPLE.COM", []string{"alice"}, [][]byte{tgtAlice})
	ccBob := buildKCMBinaryCCache(0, true, "EXAMPLE.COM", []string{"bob"}, [][]byte{tgtBob})

	// Second entry exercises RFC 4514 escaping of comma and backslash in the
	// cache name (e.g. KCM:2000:foo,bar\baz).
	ldif := fmt.Sprintf(`dn: cn=persistent,cn=kcm
type: container
creationTime: 1700000000

dn: cn=1000,cn=persistent,cn=kcm
type: container
creationTime: 1700000000

dn: cn=ccache,cn=1000,cn=persistent,cn=kcm
type: container
creationTime: 1700000000

dn: cn=default,cn=1000,cn=persistent,cn=kcm
secret: 11111111-2222-3333-4444-555555555555
creationTime: 1700000000

dn: cn=11111111-2222-3333-4444-555555555555-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm
secret:: %s
creationTime: 1700000000

dn: cn=2000,cn=persistent,cn=kcm
type: container
creationTime: 1700000000

dn: cn=ccache,cn=2000,cn=persistent,cn=kcm
type: container
creationTime: 1700000000

dn: cn=22222222-2222-2222-2222-222222222222-2000:foo\,bar\\baz,cn=ccache,cn=2000,cn=persistent,cn=kcm
secret:: %s
creationTime: 1700000000
`, base64.StdEncoding.EncodeToString(ccAlice), base64.StdEncoding.EncodeToString(ccBob))

	setTestFSGuard(t, false, []mountEntry{{mountPoint: "/", fsType: "ext4"}})
	dbPath := writeTestLDBWithLdbadd(t, ldif)

	caches, err := loadKCMSecretsDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("loadKCMSecretsDB() unexpected error: %v", err)
	}
	byUID := make(map[string][]ccacheCredential, len(caches))
	for _, cc := range caches {
		byUID[cc.UID] = append(byUID[cc.UID], cc.Creds...)
	}
	if len(byUID["1000"]) != 1 || byUID["1000"][0].ClientPrincipal != "alice" || byUID["1000"][0].ServerPrincipal != "krbtgt/EXAMPLE.COM" {
		t.Fatalf("uid 1000 creds = %+v", byUID["1000"])
	}
	if len(byUID["2000"]) != 1 || byUID["2000"][0].ClientPrincipal != "bob" || byUID["2000"][0].ServerPrincipal != "krbtgt/EXAMPLE.COM" {
		t.Fatalf("uid 2000 (escaped comma/backslash RDN) creds = %+v", byUID["2000"])
	}
}

func TestParseKCMSecretsDBUnsupportedFormats(t *testing.T) {
	kcmKey := []byte("DN=CN=11111111-2222-3333-4444-555555555555-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00")
	kcmDN := "cn=11111111-2222-3333-4444-555555555555-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm"

	mutexTDB := buildTDB(binary.LittleEndian, nil)
	binary.LittleEndian.PutUint32(mutexTDB[40:44], tdbFeatureFlagMagic)
	binary.LittleEndian.PutUint32(mutexTDB[60:64], tdbFeatureFlagMutex)

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "legacy_sssd_pre_2_4_1_type_simple_masterkey",
			data: buildTDB(binary.LittleEndian, []testTDBEntry{{
				key: kcmKey,
				data: buildLDBRecordV1(kcmDN, []testLDBAttr{
					{name: "type", vals: [][]byte{[]byte("simple")}},
					{name: "enctype", vals: [][]byte{[]byte("masterkey")}},
					{name: "secret", vals: [][]byte{[]byte("bGVnYWN5")}},
				}),
			}}),
		},
		{
			name: "encrypted_binary_enctype_masterkey",
			data: buildTDB(binary.LittleEndian, []testTDBEntry{{
				key: kcmKey,
				data: buildLDBRecordV1(kcmDN, []testLDBAttr{
					{name: "type", vals: [][]byte{[]byte("binary")}},
					{name: "enctype", vals: [][]byte{[]byte("masterkey")}},
					{name: "secret", vals: [][]byte{[]byte("bGVnYWN5")}},
				}),
			}}),
		},
		{
			name: "ldb_pack_format_v2_unsupported",
			data: buildTDB(binary.LittleEndian, []testTDBEntry{{
				key:  kcmKey,
				data: []byte{0x68, 0x19, 0x01, 0x26, 0x00, 0x00, 0x00, 0x00},
			}}),
		},
		{
			name: "raw_json_payload_bad_present_byte",
			data: buildTDB(binary.LittleEndian, []testTDBEntry{{
				key: kcmKey,
				data: buildLDBRecordV1(kcmDN, []testLDBAttr{
					{name: "secret", vals: [][]byte{[]byte(`{"version":1,"kdc_offset":0}`)}},
				}),
			}}),
		},
		{
			name: "trailing_bytes_in_cred_blob",
			data: buildTDB(binary.LittleEndian, []testTDBEntry{{
				key: kcmKey,
				data: buildLDBRecordV1(kcmDN, []testLDBAttr{
					{name: "secret", vals: [][]byte{buildKCMBinaryCCache(0, false, "", nil, [][]byte{append(bytes.Clone(mitMarshalV4Cred1), 0x01)})}},
				}),
			}}),
		},
		{
			name: "tdb_mutex_locking_unsupported",
			data: mutexTDB,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseKCMSecretsDB(tc.data)
			if !errors.Is(err, errUnsupportedKCMFormat) {
				t.Fatalf("parseKCMSecretsDB(%s) err = %v, want errUnsupportedKCMFormat", tc.name, err)
			}
		})
	}
}

func TestParseKCMSecretsDBPartialRecovery(t *testing.T) {
	ccValid1 := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"testclient"}, [][]byte{mitMarshalV4Cred1})
	ccValid2 := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"testclient"}, [][]byte{mitMarshalV4Cred2})

	t.Run("mixed_corrupt_legacy_and_valid_records", func(t *testing.T) {
		raw := buildTDB(binary.LittleEndian, []testTDBEntry{
			{
				key:  []byte("DN=CN=11111111-1111-1111-1111-111111111111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=11111111-1111-1111-1111-111111111111-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccValid1}}}),
			},
			{
				// Stale pre-2.4.1 legacy record left on an upgraded host.
				key: []byte("DN=CN=22222222-2222-2222-2222-222222222222-1500,CN=CCACHE,CN=1500,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=22222222-2222-2222-2222-222222222222-1500,cn=ccache,cn=1500,cn=persistent,cn=kcm", []testLDBAttr{
					{name: "type", vals: [][]byte{[]byte("simple")}},
					{name: "enctype", vals: [][]byte{[]byte("masterkey")}},
					{name: "secret", vals: [][]byte{[]byte("bGVnYWN5")}},
				}),
			},
			{
				// Corrupt / truncated payload (e.g. mid-write).
				key:  []byte("DN=CN=33333333-3333-3333-3333-333333333333-1600,CN=CCACHE,CN=1600,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=33333333-3333-3333-3333-333333333333-1600,cn=ccache,cn=1600,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{[]byte{0, 0, 0}}}}),
			},
			{
				key:  []byte("DN=CN=44444444-4444-4444-4444-444444444444-2000,CN=CCACHE,CN=2000,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=44444444-4444-4444-4444-444444444444-2000,cn=ccache,cn=2000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccValid2}}}),
			},
		})

		caches, err := parseKCMSecretsDB(raw)
		if !errors.Is(err, errUnsupportedKCMFormat) {
			t.Fatalf("parseKCMSecretsDB() err = %v, want wrapping errUnsupportedKCMFormat", err)
		}
		gotUIDs := make(map[string]int, len(caches))
		for _, cc := range caches {
			gotUIDs[cc.UID] += len(cc.Creds)
		}
		if gotUIDs["1000"] != 1 || gotUIDs["2000"] != 1 || len(gotUIDs) != 2 {
			t.Fatalf("recovered caches = %+v, want UIDs 1000 and 2000", gotUIDs)
		}
	})

	t.Run("corrupt_record_does_not_drop_valid_siblings", func(t *testing.T) {
		raw := buildTDB(binary.LittleEndian, []testTDBEntry{
			{
				key:  []byte("DN=CN=11111111-1111-1111-1111-111111111111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=11111111-1111-1111-1111-111111111111-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccValid1}}}),
			},
			{
				key:  []byte("DN=CN=33333333-3333-3333-3333-333333333333-1600,CN=CCACHE,CN=1600,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=33333333-3333-3333-3333-333333333333-1600,cn=ccache,cn=1600,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{[]byte{0, 0}}}}),
			},
		})

		caches, err := parseKCMSecretsDB(raw)
		if err == nil || errors.Is(err, errUnsupportedKCMFormat) {
			t.Fatalf("parseKCMSecretsDB() err = %v, want non-nil non-unsupported error", err)
		}
		if len(caches) != 1 || caches[0].UID != "1000" {
			t.Fatalf("recovered caches = %+v, want UID 1000", caches)
		}
	})
}

func TestWalkTDBDeadMagic(t *testing.T) {
	// Samba TDB marks records deleted during an active traversal with
	// TDB_DEAD_MAGIC (0xFEE1DEAD) while leaving them linked in the hash chain.
	cc1 := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"testclient"}, [][]byte{mitMarshalV4Cred1})
	cc2 := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"testclient"}, [][]byte{mitMarshalV4Cred2})

	raw := buildTDB(binary.LittleEndian, []testTDBEntry{
		{
			key:  []byte("DN=CN=11111111-1111-1111-1111-111111111111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=11111111-1111-1111-1111-111111111111-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{cc1}}}),
		},
		{
			key:  []byte("DN=CN=DEAD-RECORD,CN=CCACHE,CN=1500,CN=PERSISTENT,CN=KCM\x00"),
			data: []byte("corrupt-dead-payload"),
		},
		{
			key:  []byte("DN=CN=22222222-2222-2222-2222-222222222222-2000,CN=CCACHE,CN=2000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=22222222-2222-2222-2222-222222222222-2000,cn=ccache,cn=2000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{cc2}}}),
		},
	})

	// Bucket 0 chain is entry[2] -> entry[1] -> entry[0]. Mark entry[1] dead
	// and scramble its keyLen/dataLen to ensure dead records are skipped purely
	// via next pointer.
	head := binary.LittleEndian.Uint32(raw[tdbHashTableOffset : tdbHashTableOffset+4])
	mid := binary.LittleEndian.Uint32(raw[head : head+4])
	binary.LittleEndian.PutUint32(raw[mid+8:mid+12], 0xdeadbeef)
	binary.LittleEndian.PutUint32(raw[mid+12:mid+16], 0xdeadbeef)
	binary.LittleEndian.PutUint32(raw[mid+20:mid+24], tdbDeadMagic)

	caches, err := parseKCMSecretsDB(raw)
	if err != nil {
		t.Fatalf("parseKCMSecretsDB(with TDB_DEAD_MAGIC) unexpected error: %v", err)
	}
	gotUIDs := make(map[string]int, len(caches))
	for _, cc := range caches {
		gotUIDs[cc.UID] += len(cc.Creds)
	}
	if gotUIDs["1000"] != 1 || gotUIDs["2000"] != 1 || len(gotUIDs) != 2 {
		t.Fatalf("caches = %+v, want UIDs 1000 and 2000", gotUIDs)
	}
}

func TestParseKCMSecretsDBTrailingIOBufSlack(t *testing.T) {
	// Real sssd_kcm writes sss_iobuf_get_size(buf) (capacity doubled from
	// sizeof(krb5_principal_data)), leaving arbitrary non-zero heap slack after
	// the last serialized credential.
	kcmKey := []byte("DN=CN=11111111-2222-3333-4444-555555555555-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00")
	kcmDN := "cn=11111111-2222-3333-4444-555555555555-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm"

	cc := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"testclient"}, [][]byte{mitMarshalV4Cred1})
	// Pad to next power-of-two multiple (like sss_iobuf's 40*2^n) with non-zero bytes.
	slack := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 100)
	ccWithSlack := append(cc, slack...)

	raw := buildTDB(binary.LittleEndian, []testTDBEntry{{
		key:  kcmKey,
		data: buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "secret", vals: [][]byte{ccWithSlack}}}),
	}})

	caches, err := parseKCMSecretsDB(raw)
	if err != nil {
		t.Fatalf("parseKCMSecretsDB(with iobuf slack) unexpected error: %v", err)
	}
	if len(caches) != 1 || caches[0].UID != "1000" || len(caches[0].Creds) != 1 ||
		caches[0].Creds[0].ClientPrincipal != "testclient" ||
		caches[0].Creds[0].ServerPrincipal != "test/host" {
		t.Fatalf("parseKCMSecretsDB(with iobuf slack) = %+v", caches)
	}
}

func TestParseKCMSecretsDBMalformedAndCycles(t *testing.T) {
	// Craft a TDB whose bucket 0 points to a record pointing back to itself.
	cyclic := buildTDB(binary.LittleEndian, []testTDBEntry{{key: []byte("k"), data: []byte("v")}})
	recOff := binary.LittleEndian.Uint32(cyclic[tdbHashTableOffset : tdbHashTableOffset+4])
	binary.LittleEndian.PutUint32(cyclic[recOff:recOff+4], recOff)

	// Craft a TDB whose bucket 0 points inside the TDB header (< dataStart).
	beforeDataStart := buildTDB(binary.LittleEndian, []testTDBEntry{{key: []byte("k"), data: []byte("v")}})
	binary.LittleEndian.PutUint32(beforeDataStart[tdbHashTableOffset:tdbHashTableOffset+4], 4)

	kcmKey := []byte("DN=CN=11111111-2222-3333-4444-555555555555-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00")
	kcmDN := "cn=11111111-2222-3333-4444-555555555555-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm"

	// Huge counts to ensure no CPU spin or OOM on malformed length prefixes.
	hugeCredCount := make([]byte, 9)
	binary.NativeEndian.PutUint32(hugeCredCount[5:9], 0xffffffff)

	hugeCompCount := make([]byte, 17)
	hugeCompCount[4] = 1 // client principal present
	// realm len = 0 (bytes 5..8), name_type = 0 (bytes 9..12)
	binary.NativeEndian.PutUint32(hugeCompCount[13:17], 0xffffffff)

	var hugeLDBElements bytes.Buffer
	_ = binary.Write(&hugeLDBElements, binary.LittleEndian, uint32(ldbPackFormatV1))
	_ = binary.Write(&hugeLDBElements, binary.LittleEndian, uint32(0xffffffff))
	hugeLDBElements.WriteString(kcmDN)
	hugeLDBElements.WriteByte(0)

	var hugeLDBVals bytes.Buffer
	_ = binary.Write(&hugeLDBVals, binary.LittleEndian, uint32(ldbPackFormatV1))
	_ = binary.Write(&hugeLDBVals, binary.LittleEndian, uint32(1))
	hugeLDBVals.WriteString(kcmDN)
	hugeLDBVals.WriteByte(0)
	hugeLDBVals.WriteString("secret")
	hugeLDBVals.WriteByte(0)
	_ = binary.Write(&hugeLDBVals, binary.LittleEndian, uint32(0xffffffff))

	nonNulPad := buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "secret", vals: [][]byte{[]byte("abc")}}})
	nonNulPad[len(nonNulPad)-1] = 0x41

	emptyAttrName := buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "", vals: [][]byte{[]byte("abc")}}})

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"bad_magic", make([]byte, 256)},
		{"bad_tdb_version", func() []byte {
			b := make([]byte, 256)
			copy(b, tdbMagicFood)
			binary.LittleEndian.PutUint32(b[32:36], 0xdeadbeef)
			return b
		}()},
		{"hash_table_oob", func() []byte {
			b := make([]byte, 256)
			copy(b, tdbMagicFood)
			binary.LittleEndian.PutUint32(b[32:36], tdbVersion)
			binary.LittleEndian.PutUint32(b[36:40], 100000)
			return b
		}()},
		{"cyclic_hash_chain", cyclic},
		{"record_offset_before_data_start", beforeDataStart},
		{"huge_cred_count", buildTDB(binary.LittleEndian, []testTDBEntry{{
			key:  kcmKey,
			data: buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "secret", vals: [][]byte{hugeCredCount}}}),
		}})},
		{"huge_comp_count", buildTDB(binary.LittleEndian, []testTDBEntry{{
			key:  kcmKey,
			data: buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "secret", vals: [][]byte{hugeCompCount}}}),
		}})},
		{"huge_ldb_num_elements", buildTDB(binary.LittleEndian, []testTDBEntry{{
			key:  kcmKey,
			data: hugeLDBElements.Bytes(),
		}})},
		{"huge_ldb_num_vals", buildTDB(binary.LittleEndian, []testTDBEntry{{
			key:  kcmKey,
			data: hugeLDBVals.Bytes(),
		}})},
		{"ldb_non_nul_value_pad", buildTDB(binary.LittleEndian, []testTDBEntry{{
			key:  kcmKey,
			data: nonNulPad,
		}})},
		{"ldb_empty_attr_name", buildTDB(binary.LittleEndian, []testTDBEntry{{
			key:  kcmKey,
			data: emptyAttrName,
		}})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKCMSecretsDB(tc.data); err == nil {
				t.Fatalf("parseKCMSecretsDB(%s) succeeded, want error", tc.name)
			}
		})
	}
}

func TestEmitKCMTicketCache(t *testing.T) {
	setTestFSGuard(t, false, []mountEntry{{mountPoint: "/", fsType: "ext4"}})
	tmp := t.TempDir()
	now := time.Unix(1700000000, 0).UTC()
	tNow := uint32(now.Unix())

	makeCred := func(client string, serverComps []string, endTime, renewTill uint32) []byte {
		return buildCCacheCred(0x0504, testCCacheCredSpec{
			client:    buildCCachePrinc(1, "KRBTEST.COM", client),
			server:    buildCCachePrinc(2, "KRBTEST.COM", serverComps...),
			enctype:   18,
			key:       []byte{1, 2, 3, 4},
			authTime:  tNow - 3600,
			startTime: tNow - 3600,
			endTime:   endTime,
			renewTill: renewTill,
			ticket:    []byte("tkt"),
		})
	}

	ccAlice := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"alice"}, [][]byte{
		makeCred("alice", []string{"krbtgt", "KRBTEST.COM"}, tNow+3600, tNow+86400),
		makeCred("alice_expired", []string{"krbtgt", "KRBTEST.COM"}, tNow-10, tNow+86400),
		makeCred("alice", []string{"cifs", "dc01.krbtest.com"}, tNow+3600, 0),
	})
	ccBob := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"bob"}, [][]byte{
		makeCred("bob", []string{"KRBTGT", "KRBTEST.COM"}, tNow+3600, 0),
	})
	ccMachine := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"host01$"}, [][]byte{
		makeCred("host01$", []string{"krbtgt", "KRBTEST.COM"}, tNow+7200, tNow+86400),
	})
	ccUnknownUID := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"ghost"}, [][]byte{
		makeCred("ghost", []string{"krbtgt", "KRBTEST.COM"}, tNow+3600, 0),
	})

	raw := buildTDB(binary.LittleEndian, []testTDBEntry{
		{
			key:  []byte("DN=CN=11111111-1111-1111-1111-111111111111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=11111111-1111-1111-1111-111111111111-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccAlice}}}),
		},
		{
			key:  []byte("DN=CN=22222222-2222-2222-2222-222222222222-2000,CN=CCACHE,CN=2000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=22222222-2222-2222-2222-222222222222-2000,cn=ccache,cn=2000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccBob}}}),
		},
		{
			key:  []byte("DN=CN=44444444-4444-4444-4444-444444444444-0,CN=CCACHE,CN=0,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=44444444-4444-4444-4444-444444444444-0,cn=ccache,cn=0,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccMachine}}}),
		},
		{
			key:  []byte("DN=CN=33333333-3333-3333-3333-333333333333-9999,CN=CCACHE,CN=9999,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=33333333-3333-3333-3333-333333333333-9999,cn=ccache,cn=9999,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccUnknownUID}}}),
		},
	})
	dbPath := filepath.Join(tmp, "secrets.ldb")
	if err := os.WriteFile(dbPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	newHost := func() *Host {
		return &Host{
			uniqueId: "host1",
			FQDN:     "host1.local",
			Users: map[string]*User{
				"0":    {UserName: "root", UID: "0", HomeDir: "/root", Shell: "/bin/bash"},
				"1000": {UserName: "alice", UID: "1000", HomeDir: "/home/alice", Shell: "/bin/bash"},
				"2000": {UserName: "bob", UID: "2000", HomeDir: "/home/bob", Shell: "/bin/bash"},
			},
			referencedUsers: make(map[string]struct{}),
		}
	}

	type kcmEdge struct {
		Kind  string `json:"kind"`
		Start struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"start"`
		End struct {
			Kind             string `json:"kind"`
			PropertyMatchers []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"property_matchers"`
		} `json:"end"`
		Properties map[string]any `json:"properties"`
	}
	unmarshalKCMEdges := func(t *testing.T, b *opengraph.GraphBuilder) []kcmEdge {
		t.Helper()
		var env struct {
			Graph struct {
				Edges []kcmEdge `json:"edges"`
			} `json:"graph"`
		}
		if err := json.Unmarshal([]byte(b.Marshal()), &env); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		return env.Graph.Edges
	}

	t.Run("default_excludes_expired_and_unknown_uid", func(t *testing.T) {
		h := newHost()
		b := opengraph.NewGraphBuilder()
		if err := emitKCMTicketCache(context.Background(), h, b, dbPath, now, false); err != nil {
			t.Fatalf("emitKCMTicketCache() unexpected error: %v", err)
		}

		got := make(map[string]kcmEdge)
		for _, e := range unmarshalKCMEdges(t, b) {
			if e.Kind != "GLH_HasTGT" || len(e.End.PropertyMatchers) != 1 {
				t.Fatalf("unexpected edge: %+v", e)
			}
			got[e.Start.Value+"->"+e.End.PropertyMatchers[0].Value] = e
		}
		type wantEdge struct {
			endKind   string
			startTime string
			endTime   string
			renewTime string
		}
		want := map[string]wantEdge{
			"1000@host1->ALICE@KRBTEST.COM": {
				endKind:   "User",
				startTime: time.Unix(int64(tNow-3600), 0).UTC().Format(time.RFC3339),
				endTime:   time.Unix(int64(tNow+3600), 0).UTC().Format(time.RFC3339),
				renewTime: time.Unix(int64(tNow+86400), 0).UTC().Format(time.RFC3339),
			},
			"2000@host1->BOB@KRBTEST.COM": {
				endKind:   "User",
				startTime: time.Unix(int64(tNow-3600), 0).UTC().Format(time.RFC3339),
				endTime:   time.Unix(int64(tNow+3600), 0).UTC().Format(time.RFC3339),
				renewTime: time.Unix(0, 0).UTC().Format(time.RFC3339),
			},
			"0@host1->HOST01.KRBTEST.COM": {
				endKind:   "Computer",
				startTime: time.Unix(int64(tNow-3600), 0).UTC().Format(time.RFC3339),
				endTime:   time.Unix(int64(tNow+7200), 0).UTC().Format(time.RFC3339),
				renewTime: time.Unix(int64(tNow+86400), 0).UTC().Format(time.RFC3339),
			},
		}
		if len(got) != len(want) {
			t.Fatalf("emitted edges = %+v, want %v", got, want)
		}
		for k, w := range want {
			e, ok := got[k]
			if !ok {
				t.Fatalf("missing expected edge %s", k)
			}
			if e.End.Kind != w.endKind {
				t.Fatalf("edge %s End.Kind = %q, want %q", k, e.End.Kind, w.endKind)
			}
			if e.Properties["TicketCacheFile"] != dbPath ||
				e.Properties["StartTime"] != w.startTime ||
				e.Properties["EndTime"] != w.endTime ||
				e.Properties["RenewTime"] != w.renewTime {
				t.Fatalf("edge %s properties = %+v, want file=%s start=%s end=%s renew=%s",
					k, e.Properties, dbPath, w.startTime, w.endTime, w.renewTime)
			}
		}
	})

	t.Run("include_expired_tgts", func(t *testing.T) {
		h := newHost()
		b := opengraph.NewGraphBuilder()
		if err := emitKCMTicketCache(context.Background(), h, b, dbPath, now, true); err != nil {
			t.Fatalf("emitKCMTicketCache(expired=true) unexpected error: %v", err)
		}
		var targets []string
		for _, e := range unmarshalKCMEdges(t, b) {
			targets = append(targets, e.Start.Value+"->"+e.End.PropertyMatchers[0].Value)
		}
		want := map[string]bool{
			"0@host1->HOST01.KRBTEST.COM":           true,
			"1000@host1->ALICE@KRBTEST.COM":         true,
			"1000@host1->ALICE_EXPIRED@KRBTEST.COM": true,
			"2000@host1->BOB@KRBTEST.COM":           true,
		}
		got := make(map[string]bool, len(targets))
		for _, k := range targets {
			got[k] = true
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("emitted edges = %v, want %v", got, want)
		}
	})

	t.Run("missing_db_and_legacy_db_gracefully_skipped", func(t *testing.T) {
		h := newHost()
		b := opengraph.NewGraphBuilder()
		if err := emitKCMTicketCache(context.Background(), h, b, filepath.Join(tmp, "missing.ldb"), now, false); err != nil {
			t.Fatalf("missing db returned error: %v", err)
		}

		legacyPath := filepath.Join(tmp, "legacy.ldb")
		legacyRaw := buildTDB(binary.LittleEndian, []testTDBEntry{{
			key: []byte("DN=CN=11111111-1111-1111-1111-111111111111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
			data: buildLDBRecordV1("cn=11111111-1111-1111-1111-111111111111-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{
				{name: "type", vals: [][]byte{[]byte("simple")}},
				{name: "enctype", vals: [][]byte{[]byte("masterkey")}},
				{name: "secret", vals: [][]byte{[]byte("bGVnYWN5")}},
			}),
		}})
		if err := os.WriteFile(legacyPath, legacyRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := emitKCMTicketCache(context.Background(), h, b, legacyPath, now, false); err != nil {
			t.Fatalf("legacy db returned error: %v", err)
		}
		if edges := unmarshalKCMEdges(t, b); len(edges) != 0 {
			t.Fatalf("expected 0 edges, got %+v", edges)
		}
	})

	t.Run("mixed_legacy_and_valid_db_emits_valid_edges", func(t *testing.T) {
		mixedPath := filepath.Join(tmp, "mixed.ldb")
		mixedRaw := buildTDB(binary.LittleEndian, []testTDBEntry{
			{
				key: []byte("DN=CN=11111111-1111-1111-1111-111111111111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=11111111-1111-1111-1111-111111111111-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm", []testLDBAttr{
					{name: "type", vals: [][]byte{[]byte("simple")}},
					{name: "enctype", vals: [][]byte{[]byte("masterkey")}},
					{name: "secret", vals: [][]byte{[]byte("bGVnYWN5")}},
				}),
			},
			{
				key:  []byte("DN=CN=22222222-2222-2222-2222-222222222222-2000,CN=CCACHE,CN=2000,CN=PERSISTENT,CN=KCM\x00"),
				data: buildLDBRecordV1("cn=22222222-2222-2222-2222-222222222222-2000,cn=ccache,cn=2000,cn=persistent,cn=kcm", []testLDBAttr{{name: "secret", vals: [][]byte{ccBob}}}),
			},
		})
		if err := os.WriteFile(mixedPath, mixedRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		h := newHost()
		b := opengraph.NewGraphBuilder()
		if err := emitKCMTicketCache(context.Background(), h, b, mixedPath, now, false); err != nil {
			t.Fatalf("emitKCMTicketCache(mixed) unexpected error: %v", err)
		}
		edges := unmarshalKCMEdges(t, b)
		if len(edges) != 1 || edges[0].Start.Value != "2000@host1" || edges[0].End.PropertyMatchers[0].Value != "BOB@KRBTEST.COM" {
			t.Fatalf("emitted edges = %+v, want only 2000@host1->BOB@KRBTEST.COM", edges)
		}
	})

	t.Run("canceled_context_returns_error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h := newHost()
		b := opengraph.NewGraphBuilder()
		if err := emitKCMTicketCache(ctx, h, b, dbPath, now, false); !errors.Is(err, context.Canceled) {
			t.Fatalf("emitKCMTicketCache(canceled) err = %v, want context.Canceled", err)
		}
	})
}

func TestExtractUIDFromTDBKey(t *testing.T) {
	cases := []struct {
		key  string
		uid  string
		want bool
	}{
		{"DN=CN=1111-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "1000", true},
		{"dn=cn=abcd,cn=ccache,cn=0,cn=persistent,cn=kcm", "0", true},
		{"DN=CN=abcd,CN=CCACHE,CN=001000,CN=PERSISTENT,CN=KCM\x00", "1000", true},
		{"DN=CN=1111-1000:FOO\\,BAR,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "1000", true},
		{"DN=CN=2222-1000:FOO\\\\BAR,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "1000", true},
		{"DN=CN=3333-1000:FOO\\\\,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "1000", true},
		{"DN=CN=4444-1000:FOO\\\\\\,BAR,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "1000", true},
		{"DN=@BASEINFO\x00", "", false},
		{"DN=CN=DEFAULT,CN=1000,CN=PERSISTENT,CN=KCM\x00", "", false},
		{"DN=CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "", false},
		{"DN=CN=,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "", false},
		{"DN=OU=X,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "", false},
		{"DN=CN=X\\,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "", false},
		{"DN=CN=X,CN=CCACHE,CN=NOTAUID,CN=PERSISTENT,CN=KCM\x00", "", false},
		{"DN=CN=X,CN=EXTRA,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00", "", false},
	}
	for _, tc := range cases {
		gotUID, gotOK := extractUIDFromTDBKey([]byte(tc.key))
		if gotOK != tc.want || gotUID != tc.uid {
			t.Errorf("extractUIDFromTDBKey(%q) = (%q, %v), want (%q, %v)", tc.key, gotUID, gotOK, tc.uid, tc.want)
		}
	}
}

func FuzzParseKCMSecretsDB(f *testing.F) {
	kcmKey := []byte("DN=CN=11111111-2222-3333-4444-555555555555-1000,CN=CCACHE,CN=1000,CN=PERSISTENT,CN=KCM\x00")
	kcmDN := "cn=11111111-2222-3333-4444-555555555555-1000,cn=ccache,cn=1000,cn=persistent,cn=kcm"
	cc := buildKCMBinaryCCache(0, true, "KRBTEST.COM", []string{"testclient"}, [][]byte{mitMarshalV4Cred1, mitMarshalV4Cred2})
	f.Add(buildTDB(binary.LittleEndian, []testTDBEntry{{
		key:  kcmKey,
		data: buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "secret", vals: [][]byte{cc}}}),
	}}))
	f.Add(buildTDB(binary.BigEndian, []testTDBEntry{{
		key:  kcmKey,
		data: buildLDBRecordV1(kcmDN, []testLDBAttr{{name: "type", vals: [][]byte{[]byte("binary")}}, {name: "enctype", vals: [][]byte{[]byte("plaintext")}}, {name: "secret", vals: [][]byte{cc}}}),
	}}))
	f.Add([]byte("TDB file\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseKCMSecretsDB(data)
	})
}
