package collect

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// Tests in this file are ported from official MIT Kerberos (github.com/krb5/krb5,
// commit 9bbee39b7275f1257c93afb372a9da00b1bca4eb):
//   - src/tests/t_keytab.py
//   - src/lib/krb5/keytab/t_keytab.c & kt_file.c
//   - src/tests/fuzzing/fuzz_keytab.c & fuzz_keytab_seed_corpus/*
//   - src/lib/krb5/ccache/t_marshal.c, t_cc.c, cc_file.c & ccmarshal.c
//   - src/lib/krb5/krb/t_cc_config.c & src/lib/krb5/ccache/ccfns.c
//   - src/tests/t_y2038.py & src/include/k5-int.h (ts2tt)
//   - src/tests/fuzzing/fuzz_ccache.c, fuzz_ccache_seed_corpus/*,
//     fuzz_marshal_cred_seed_corpus/* & fuzz_marshal_princ_seed_corpus/*

// Raw binary fixtures from MIT krb5 src/lib/krb5/ccache/t_marshal.c (tests[0..3]).
var (
	mitMarshalV1Header = []byte("\x05\x01")
	mitMarshalV1Princ  = []byte(
		"\x02\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54\x45\x53\x54\x2E" +
			"\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63\x6C\x69\x65\x6E" +
			"\x74",
	)
	mitMarshalV1Cred1 = []byte(
		"\x02\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54\x45\x53\x54\x2E" +
			"\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63\x6C\x69\x65\x6E" +
			"\x74\x03\x00\x00\x00\x0B\x00\x00\x00\x45\x58\x41\x4D\x50\x4C\x45" +
			"\x2E\x43\x4F\x4D\x04\x00\x00\x00\x74\x65\x73\x74\x04\x00\x00\x00" +
			"\x68\x6F\x73\x74\x11\x00\x10\x00\x00\x00\x00\x01\x02\x03\x04\x05" +
			"\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x0B\x00\x00\x00\xDE\x00" +
			"\x00\x00\x05\x0D\x00\x00\x00\xCA\x9A\x3B\x00\x00\x00\x80\x40\x01" +
			"\x00\x00\x00\x02\x00\x04\x00\x00\x00\x0A\x00\x00\x01\x02\x00\x00" +
			"\x00\x00\x02\x0A\x00\x00\x00\x73\x69\x67\x6E\x74\x69\x63\x6B\x65" +
			"\x74\x9C\xFF\x00\x00\x00\x00\x06\x00\x00\x00\x74\x69\x63\x6B\x65" +
			"\x74\x00\x00\x00\x00",
	)
	mitMarshalV1Cred2 = []byte(
		"\x02\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54\x45\x53\x54\x2E" +
			"\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63\x6C\x69\x65\x6E" +
			"\x74\x01\x00\x00\x00\x00\x00\x00\x00\x17\x00\x10\x00\x00\x00\x0F" +
			"\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00" +
			"\x74\x69\x63\x6B\x65\x74\x07\x00\x00\x00\x32\x74\x69\x63\x6B\x65" +
			"\x74",
	)

	mitMarshalV2Header = []byte("\x05\x02")
	mitMarshalV2Princ  = []byte(
		"\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74",
	)
	mitMarshalV2Cred1 = []byte(
		"\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74\x01\x00\x00\x00\x02\x00\x00\x00\x0B\x00\x00" +
			"\x00\x45\x58\x41\x4D\x50\x4C\x45\x2E\x43\x4F\x4D\x04\x00\x00\x00" +
			"\x74\x65\x73\x74\x04\x00\x00\x00\x68\x6F\x73\x74\x11\x00\x10\x00" +
			"\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D" +
			"\x0E\x0F\x0B\x00\x00\x00\xDE\x00\x00\x00\x05\x0D\x00\x00\x00\xCA" +
			"\x9A\x3B\x00\x00\x00\x80\x40\x01\x00\x00\x00\x02\x00\x04\x00\x00" +
			"\x00\x0A\x00\x00\x01\x02\x00\x00\x00\x00\x02\x0A\x00\x00\x00\x73" +
			"\x69\x67\x6E\x74\x69\x63\x6B\x65\x74\x9C\xFF\x00\x00\x00\x00\x06" +
			"\x00\x00\x00\x74\x69\x63\x6B\x65\x74\x00\x00\x00\x00",
	)
	mitMarshalV2Cred2 = []byte(
		"\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x17\x00\x10\x00\x00\x00\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07" +
			"\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x06\x00\x00\x00\x74\x69\x63\x6B\x65\x74\x07\x00" +
			"\x00\x00\x32\x74\x69\x63\x6B\x65\x74",
	)

	mitMarshalV3Header = []byte("\x05\x03")
	mitMarshalV3Princ  = []byte(
		"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74",
	)
	mitMarshalV3Cred1 = []byte(
		"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00" +
			"\x0B\x45\x58\x41\x4D\x50\x4C\x45\x2E\x43\x4F\x4D\x00\x00\x00\x04" +
			"\x74\x65\x73\x74\x00\x00\x00\x04\x68\x6F\x73\x74\x00\x11\x00\x11" +
			"\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B" +
			"\x0C\x0D\x0E\x0F\x00\x00\x00\x0B\x00\x00\x00\xDE\x00\x00\x0D\x05" +
			"\x3B\x9A\xCA\x00\x00\x40\x80\x00\x00\x00\x00\x00\x01\x00\x02\x00" +
			"\x00\x00\x04\x0A\x00\x00\x01\x00\x00\x00\x02\x02\x00\x00\x00\x00" +
			"\x0A\x73\x69\x67\x6E\x74\x69\x63\x6B\x65\x74\xFF\x9C\x00\x00\x00" +
			"\x00\x00\x00\x00\x06\x74\x69\x63\x6B\x65\x74\x00\x00\x00\x00",
	)
	mitMarshalV3Cred2 = []byte(
		"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x17\x00\x17\x00\x00\x00\x10\x0F\x0E\x0D\x0C\x0B\x0A\x09" +
			"\x08\x07\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x74\x69\x63\x6B\x65\x74" +
			"\x00\x00\x00\x07\x32\x74\x69\x63\x6B\x65\x74",
	)

	mitMarshalV4Header = []byte("\x05\x04\x00\x0C\x00\x01\x00\x08\x00\x00\x01\x2C\x00\x00\xD4\x31")
	mitMarshalV4Princ  = []byte(
		"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74",
	)
	mitMarshalV4Cred1 = []byte(
		"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00" +
			"\x0B\x45\x58\x41\x4D\x50\x4C\x45\x2E\x43\x4F\x4D\x00\x00\x00\x04" +
			"\x74\x65\x73\x74\x00\x00\x00\x04\x68\x6F\x73\x74\x00\x11\x00\x00" +
			"\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D" +
			"\x0E\x0F\x00\x00\x00\x0B\x00\x00\x00\xDE\x00\x00\x0D\x05\x3B\x9A" +
			"\xCA\x00\x00\x40\x80\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00" +
			"\x04\x0A\x00\x00\x01\x00\x00\x00\x02\x02\x00\x00\x00\x00\x0A\x73" +
			"\x69\x67\x6E\x74\x69\x63\x6B\x65\x74\xFF\x9C\x00\x00\x00\x00\x00" +
			"\x00\x00\x06\x74\x69\x63\x6B\x65\x74\x00\x00\x00\x00",
	)
	mitMarshalV4Cred2 = []byte(
		"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54" +
			"\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63" +
			"\x6C\x69\x65\x6E\x74\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x17\x00\x00\x00\x10\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07" +
			"\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x06\x74\x69\x63\x6B\x65\x74\x00\x00" +
			"\x00\x07\x32\x74\x69\x63\x6B\x65\x74",
	)
)

// Raw binary seeds from MIT krb5 src/tests/fuzzing/fuzz_keytab_seed_corpus/*
// and src/tests/fuzzing/fuzz_ccache_seed_corpus/*.
var (
	mitFuzzKeytabV502OneEntry = []byte(
		"\x05\x02\x00\x00\x00\x3c\x00\x01\x00\x05REALM\x00\x04user" +
			"\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x20" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	)
	mitFuzzKeytabVersionOnly  = []byte("\x05\x02")
	mitFuzzKeytabVersion0x501 = []byte("\x05\x01")
	mitFuzzKeytabBigSizeV1    = []byte(
		"\x05\x01\xff\xff\xff\x7f\x02\x00\x01\x00\xff\x01\x00\x20\xff\x20" +
			"\x20\xff\x20\xff\x20\x01\x00\x20\xff\x20\xff\x20",
	)

	mitFuzzCCacheV1PrincipalOnly = []byte(
		"\x05\x01\x01\x00\x00\x00\x02\x00\x00\x00\x05\x00\x00\x00REALM\x04\x00\x00\x00user",
	)
	mitFuzzCCacheV4PrincipalOnly = []byte(
		"\x05\x04\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x05REALM\x00\x00\x00\x04user",
	)
)

// Hand-crafted keytab record from MIT krb5 src/tests/t_keytab.py (mark('32-bit kvno'), L115-123).
func mitTKeytabPyBaseRecord() []byte {
	var b bytes.Buffer
	b.Write([]byte("\x00\x01"))             // principal component count (1)
	b.Write([]byte("\x00\x0bKRBTEST.COM"))  // realm
	b.Write([]byte("\x00\x04user"))         // principal component
	b.Write([]byte("\x00\x00\x00\x01"))     // name type (NT-PRINCIPAL)
	b.Write([]byte("\x54\xf7\x4d\x35"))     // timestamp
	b.WriteByte(0x02)                       // 8-bit key version (2)
	b.Write([]byte("\x00\x12"))             // enctype (AES256-CTS)
	b.Write([]byte("\x00\x20"))             // key length (32)
	b.Write(bytes.Repeat([]byte{0x00}, 32)) // key bytes
	return b.Bytes()
}

// buildV2KeytabEntry serializes one MIT v2 keytab entry body according to
// src/lib/krb5/keytab/kt_file.c:krb5_ktfileint_write_entry.
func buildV2KeytabEntryBody(realm string, components []string, nameType, timestamp uint32, vno8 uint8, enctype uint16, key []byte, vno32 *uint32) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(len(components)))
	_ = binary.Write(&b, binary.BigEndian, uint16(len(realm)))
	b.WriteString(realm)
	for _, c := range components {
		_ = binary.Write(&b, binary.BigEndian, uint16(len(c)))
		b.WriteString(c)
	}
	_ = binary.Write(&b, binary.BigEndian, nameType)
	_ = binary.Write(&b, binary.BigEndian, timestamp)
	b.WriteByte(vno8)
	_ = binary.Write(&b, binary.BigEndian, enctype)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(key)))
	b.Write(key)
	if vno32 != nil {
		_ = binary.Write(&b, binary.BigEndian, *vno32)
	}
	return b.Bytes()
}

func appendKeytabRecord(dst []byte, recordSize int32, body []byte) []byte {
	var sz [4]byte
	binary.BigEndian.PutUint32(sz[:], uint32(recordSize))
	dst = append(dst, sz[:]...)
	dst = append(dst, body...)
	return dst
}

// buildCCachePrinc marshals a v3/v4 principal according to
// src/lib/krb5/ccache/ccmarshal.c:k5_marshal_princ.
func buildCCachePrinc(nameType uint32, realm string, components ...string) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, nameType)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(components)))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(realm)))
	b.WriteString(realm)
	for _, c := range components {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(c)))
		b.WriteString(c)
	}
	return b.Bytes()
}

type testCCacheAddr struct {
	addrType uint16
	data     []byte
}

type testCCacheAuthData struct {
	adType int16
	data   []byte
}

type testCCacheCredSpec struct {
	client       []byte
	server       []byte
	enctype      uint16
	key          []byte
	authTime     uint32
	startTime    uint32
	endTime      uint32
	renewTill    uint32
	isSKey       uint8
	ticketFlags  uint32
	addrs        []testCCacheAddr
	authData     []testCCacheAuthData
	ticket       []byte
	secondTicket []byte
}

// buildCCacheCred marshals a v3 or v4 credential according to
// src/lib/krb5/ccache/ccmarshal.c:k5_marshal_cred.
func buildCCacheCred(version uint16, spec testCCacheCredSpec) []byte {
	var b bytes.Buffer
	b.Write(spec.client)
	b.Write(spec.server)
	_ = binary.Write(&b, binary.BigEndian, spec.enctype)
	if version == 0x0503 {
		// Version 3 repeats the 16-bit enctype twice (ccmarshal.c:marshal_keyblock).
		_ = binary.Write(&b, binary.BigEndian, spec.enctype)
	}
	_ = binary.Write(&b, binary.BigEndian, uint32(len(spec.key)))
	b.Write(spec.key)
	_ = binary.Write(&b, binary.BigEndian, spec.authTime)
	_ = binary.Write(&b, binary.BigEndian, spec.startTime)
	_ = binary.Write(&b, binary.BigEndian, spec.endTime)
	_ = binary.Write(&b, binary.BigEndian, spec.renewTill)
	b.WriteByte(spec.isSKey)
	_ = binary.Write(&b, binary.BigEndian, spec.ticketFlags)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(spec.addrs)))
	for _, a := range spec.addrs {
		_ = binary.Write(&b, binary.BigEndian, a.addrType)
		_ = binary.Write(&b, binary.BigEndian, uint32(len(a.data)))
		b.Write(a.data)
	}
	_ = binary.Write(&b, binary.BigEndian, uint32(len(spec.authData)))
	for _, ad := range spec.authData {
		_ = binary.Write(&b, binary.BigEndian, uint16(ad.adType))
		_ = binary.Write(&b, binary.BigEndian, uint32(len(ad.data)))
		b.Write(ad.data)
	}
	_ = binary.Write(&b, binary.BigEndian, uint32(len(spec.ticket)))
	b.Write(spec.ticket)
	_ = binary.Write(&b, binary.BigEndian, uint32(len(spec.secondTicket)))
	b.Write(spec.secondTicket)
	return b.Bytes()
}

// TestParseKeytabMIT32BitKVNO ports the three hand-crafted v2 keytab records from
// MIT krb5 src/tests/t_keytab.py (mark('32-bit kvno'), lines 111-147):
//  1. Entry without a 32-bit kvno suffix (reports 8-bit kvno)
//  2. Entry with 4 bytes of trailing zero-fill padding
//  3. Entry with an explicit 4-byte 32-bit kvno suffix (0x00000003)
func TestParseKeytabMIT32BitKVNO(t *testing.T) {
	record := mitTKeytabPyBaseRecord()
	want := []keytabEntry{{
		Principal: "user@KRBTEST.COM",
		Realm:     "KRBTEST.COM",
	}}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "no_32bit_kvno",
			data: appendKeytabRecord([]byte("\x05\x02"), int32(len(record)), record),
		},
		{
			name: "zero_fill_padding",
			data: appendKeytabRecord([]byte("\x05\x02"), int32(len(record)+4), append(bytes.Clone(record), 0, 0, 0, 0)),
		},
		{
			name: "explicit_32bit_kvno",
			data: appendKeytabRecord([]byte("\x05\x02"), int32(len(record)+4), append(bytes.Clone(record), 0, 0, 0, 3)),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseKeytab(tc.data)
			if err != nil {
				t.Fatalf("parseKeytab() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parseKeytab() = %+v, want %+v", got, want)
			}
		})
	}
}

// TestParseKeytabMITMultiEntryAndHoles ports the keytab sequence, deletion hole,
// slot reuse, and EOF sentinel semantics from MIT krb5 src/lib/krb5/keytab/t_keytab.c
// (kt_test, lines 141-388) and src/lib/krb5/keytab/kt_file.c.
func TestParseKeytabMITMultiEntryAndHoles(t *testing.T) {
	const (
		enctypeAES128SHA256 = 19 // ENCTYPE_AES128_CTS_HMAC_SHA256_128
		enctypeAES256SHA384 = 20 // ENCTYPE_AES256_CTS_HMAC_SHA384_192
		ktTimestamp         = 327689
	)
	vno1 := uint32(1)
	vno2 := uint32(2)

	// The 3 entries added by t_keytab.c:kt_test for test/test2@TEST.MIT.EDU.
	ent1 := buildV2KeytabEntryBody("TEST.MIT.EDU", []string{"test", "test2"}, 1, ktTimestamp, 1, enctypeAES128SHA256, []byte("1"), &vno1)
	ent2 := buildV2KeytabEntryBody("TEST.MIT.EDU", []string{"test", "test2"}, 1, ktTimestamp, 1, enctypeAES256SHA384, []byte("1"), &vno1)
	ent3 := buildV2KeytabEntryBody("TEST.MIT.EDU", []string{"test", "test2"}, 1, ktTimestamp, 2, enctypeAES128SHA256, []byte("2"), &vno2)
	hostEnt := buildV2KeytabEntryBody("TEST.MIT.EDU", []string{"host", "db.test.mit.edu"}, 1, ktTimestamp, 3, enctypeAES256SHA384, []byte("secretkey"), &vno2)

	wantTestPrinc := keytabEntry{
		Principal: "test/test2@TEST.MIT.EDU",
		Realm:     "TEST.MIT.EDU",
	}
	wantHostPrinc := keytabEntry{
		Principal: "host/db.test.mit.edu@TEST.MIT.EDU",
		Realm:     "TEST.MIT.EDU",
	}

	t.Run("three_entries_multi_component", func(t *testing.T) {
		kt := []byte("\x05\x02")
		kt = appendKeytabRecord(kt, int32(len(ent1)), ent1)
		kt = appendKeytabRecord(kt, int32(len(ent2)), ent2)
		kt = appendKeytabRecord(kt, int32(len(ent3)), ent3)

		got, err := parseKeytab(kt)
		if err != nil {
			t.Fatalf("parseKeytab() unexpected error: %v", err)
		}
		want := []keytabEntry{wantTestPrinc, wantTestPrinc, wantTestPrinc}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseKeytab() = %+v, want %+v", got, want)
		}
	})

	t.Run("deleted_entry_holes", func(t *testing.T) {
		// kt_file.c:krb5_ktfileint_delete_entry overwrites the 32-bit size with
		// -size and zeroes the entry body. Exercise holes at the start, middle,
		// consecutive, and end of the keytab.
		kt := []byte("\x05\x02")
		kt = appendKeytabRecord(kt, -int32(len(ent1)), make([]byte, len(ent1)))
		kt = appendKeytabRecord(kt, int32(len(ent1)), ent1)
		kt = appendKeytabRecord(kt, -int32(len(ent2)), make([]byte, len(ent2)))
		kt = appendKeytabRecord(kt, -int32(len(ent3)), make([]byte, len(ent3)))
		kt = appendKeytabRecord(kt, int32(len(hostEnt)), hostEnt)
		kt = appendKeytabRecord(kt, -int32(len(ent3)), make([]byte, len(ent3)))

		got, err := parseKeytab(kt)
		if err != nil {
			t.Fatalf("parseKeytab() unexpected error: %v", err)
		}
		want := []keytabEntry{wantTestPrinc, wantHostPrinc}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseKeytab() = %+v, want %+v", got, want)
		}
	})

	t.Run("reused_oversized_hole", func(t *testing.T) {
		// kt_file.c:krb5_ktfileint_find_slot reuses a hole whose size is >= size_needed,
		// leaving trailing slack bytes inside the record after the 32-bit kvno.
		padded := append(bytes.Clone(ent1), make([]byte, 19)...)
		kt := []byte("\x05\x02")
		kt = appendKeytabRecord(kt, int32(len(padded)), padded)
		kt = appendKeytabRecord(kt, int32(len(hostEnt)), hostEnt)

		got, err := parseKeytab(kt)
		if err != nil {
			t.Fatalf("parseKeytab() unexpected error: %v", err)
		}
		want := []keytabEntry{wantTestPrinc, wantHostPrinc}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseKeytab() = %+v, want %+v", got, want)
		}
	})

	t.Run("zero_size_eof_sentinel", func(t *testing.T) {
		// doc/formats/keytab_file_format.rst & kt_file.c:933: a record length of 0
		// indicates the end of the file even if trailing bytes exist on disk.
		kt := []byte("\x05\x02")
		kt = appendKeytabRecord(kt, int32(len(ent1)), ent1)
		kt = append(kt, 0x00, 0x00, 0x00, 0x00) // size == 0 sentinel
		kt = append(kt, 0xFF, 0xFF, 0xFF, 0xFF) // unreferenced bytes after sentinel

		got, err := parseKeytab(kt)
		if err != nil {
			t.Fatalf("parseKeytab() unexpected error: %v", err)
		}
		want := []keytabEntry{wantTestPrinc}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseKeytab() = %+v, want %+v", got, want)
		}
	})
}

// TestParseKeytabMITFuzzSeeds runs the exact seed corpus files from
// MIT krb5 src/tests/fuzzing/fuzz_keytab_seed_corpus/*.
func TestParseKeytabMITFuzzSeeds(t *testing.T) {
	t.Run("v502_one_entry", func(t *testing.T) {
		got, err := parseKeytab(mitFuzzKeytabV502OneEntry)
		if err != nil {
			t.Fatalf("parseKeytab(v502_one_entry) unexpected error: %v", err)
		}
		want := []keytabEntry{{
			Principal: "user@REALM",
			Realm:     "REALM",
		}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseKeytab(v502_one_entry) = %+v, want %+v", got, want)
		}
	})

	t.Run("version_only", func(t *testing.T) {
		got, err := parseKeytab(mitFuzzKeytabVersionOnly)
		if err != nil {
			t.Fatalf("parseKeytab(version_only) unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("parseKeytab(version_only) = %+v, want empty", got)
		}
	})

	t.Run("version_0x501_unsupported", func(t *testing.T) {
		if _, err := parseKeytab(mitFuzzKeytabVersion0x501); err == nil {
			t.Fatal("parseKeytab(version_0x501) succeeded, want error")
		}
	})

	t.Run("big_size_v1", func(t *testing.T) {
		if _, err := parseKeytab(mitFuzzKeytabBigSizeV1); err == nil {
			t.Fatal("parseKeytab(big_size_v1) succeeded, want error")
		}
	})

	t.Run("big_size_v2_header", func(t *testing.T) {
		// Same oversized record payload with v2 big-endian header 0x0502.
		in := bytes.Clone(mitFuzzKeytabBigSizeV1)
		in[1] = 0x02
		if _, err := parseKeytab(in); err == nil {
			t.Fatal("parseKeytab(big_size_v2_header) succeeded, want error")
		}
	})
}

// TestParseKeytabMalformed covers MIT krb5 kt_file.c validation checks and
// regression #8914 (src/tests/t_keytab.py:201-207).
func TestParseKeytabMalformed(t *testing.T) {
	validBody := mitTKeytabPyBaseRecord()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty_input",
			data: nil,
		},
		{
			name: "one_byte_header",
			data: []byte{0x05},
		},
		{
			name: "legacy_v1_header",
			data: appendKeytabRecord([]byte("\x05\x01"), int32(len(validBody)), validBody),
		},
		{
			name: "unknown_version_0503",
			data: []byte("\x05\x03\x00\x00\x00\x00"),
		},
		{
			name: "unknown_major_version_0402",
			data: []byte("\x04\x02\x00\x00\x00\x00"),
		},
		{
			name: "truncated_record_size_1_byte",
			data: []byte("\x05\x02\x00"),
		},
		{
			name: "truncated_record_size_3_bytes",
			data: []byte("\x05\x02\x00\x00\x00"),
		},
		{
			// MIT krb5 ticket #8914 regression test from src/tests/t_keytab.py:204.
			name: "int32_min_record_length_issue_8914",
			data: []byte("\x05\x02\x80\x00\x00\x00"),
		},
		{
			name: "int32_max_record_length",
			data: []byte("\x05\x02\x7f\xff\xff\xff\x00\x01"),
		},
		{
			name: "negative_hole_exceeding_buffer",
			data: []byte("\x05\x02\xff\xff\xff\xf0\x00\x00\x00\x00"),
		},
		{
			name: "positive_size_exceeding_buffer",
			data: appendKeytabRecord([]byte("\x05\x02"), int32(len(validBody)+1), validBody),
		},
		{
			name: "record_too_short_for_component_count",
			data: appendKeytabRecord([]byte("\x05\x02"), 1, []byte{0x00}),
		},
		{
			// kt_file.c:951 rejects count == 0.
			name: "zero_component_count",
			data: appendKeytabRecord([]byte("\x05\x02"), 20, []byte("\x00\x00\x00\x05REALM\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x01k")),
		},
		{
			// kt_file.c:951 rejects negative int16 component count.
			name: "negative_int16_component_count",
			data: appendKeytabRecord([]byte("\x05\x02"), 20, []byte("\xff\xff\x00\x05REALM\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x01k")),
		},
		{
			name: "component_count_exceeds_record_bytes",
			data: appendKeytabRecord([]byte("\x05\x02"), 10, []byte("\x00\x10\x00\x05REALM\x00")),
		},
		{
			// kt_file.c:975 rejects empty realm (princ_size == 0).
			name: "empty_realm",
			data: appendKeytabRecord([]byte("\x05\x02"), 23, []byte("\x00\x01\x00\x00\x00\x04user\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x01k")),
		},
		{
			name: "truncated_realm",
			data: appendKeytabRecord([]byte("\x05\x02"), 6, []byte("\x00\x01\x00\x0bKR")),
		},
		{
			// kt_file.c:1005 rejects empty component (princ_size == 0).
			name: "empty_component",
			data: appendKeytabRecord([]byte("\x05\x02"), 24, []byte("\x00\x01\x00\x05REALM\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x01k")),
		},
		{
			name: "truncated_component",
			data: appendKeytabRecord([]byte("\x05\x02"), 13, []byte("\x00\x01\x00\x05REALM\x00\x04us")),
		},
		{
			name: "truncated_metadata_after_principal",
			data: appendKeytabRecord([]byte("\x05\x02"), 20, []byte("\x00\x01\x00\x05REALM\x00\x04user\x00\x00\x00\x01\x00\x00")),
		},
		{
			// kt_file.c:1067 rejects empty key (count == 0).
			name: "empty_key_contents",
			data: appendKeytabRecord([]byte("\x05\x02"), 26, []byte("\x00\x01\x00\x05REALM\x00\x04user\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x00")),
		},
		{
			name: "truncated_key_contents",
			data: appendKeytabRecord([]byte("\x05\x02"), 28, []byte("\x00\x01\x00\x05REALM\x00\x04user\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x12\x00\x10ab")),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKeytab(tc.data); err == nil {
				t.Fatalf("parseKeytab(%s) succeeded, want error", tc.name)
			}
		})
	}
}

// TestParseKeytabPartialRecovery verifies that entries decoded prior to a
// truncated trailing keytab record are still returned alongside the error.
func TestParseKeytabPartialRecovery(t *testing.T) {
	record := mitTKeytabPyBaseRecord()
	kt := appendKeytabRecord([]byte("\x05\x02"), int32(len(record)), record)
	kt = append(kt, 0x00, 0x00) // truncated second entry size

	got, err := parseKeytab(kt)
	if err == nil {
		t.Fatal("parseKeytab() succeeded on truncated second record, want error")
	}
	want := []keytabEntry{{
		Principal: "user@KRBTEST.COM",
		Realm:     "KRBTEST.COM",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseKeytab() partial entries = %+v, want %+v", got, want)
	}
}

// TestParseCCacheMITMarshal ports the canonical ccache test vectors from
// MIT krb5 src/lib/krb5/ccache/t_marshal.c (tests[0..3], verify_cred1, verify_cred2).
func TestParseCCacheMITMarshal(t *testing.T) {
	wantCreds := []ccacheCredential{
		{
			ClientPrincipal: "testclient",
			ClientRealm:     "KRBTEST.COM",
			ServerPrincipal: "test/host",
			StartTime:       time.Unix(222, 0),
			EndTime:         time.Unix(3333, 0),
			RenewTill:       time.Unix(1000000000, 0),
		},
		{
			ClientPrincipal: "testclient",
			ClientRealm:     "KRBTEST.COM",
			ServerPrincipal: "",
			StartTime:       time.Unix(0, 0),
			EndTime:         time.Unix(0, 0),
			RenewTill:       time.Unix(0, 0),
		},
	}

	t.Run("v3_full_fixture", func(t *testing.T) {
		raw := bytes.Join([][]byte{
			mitMarshalV3Header,
			mitMarshalV3Princ,
			mitMarshalV3Cred1,
			mitMarshalV3Cred2,
		}, nil)
		got, err := parseCCache(raw)
		if err != nil {
			t.Fatalf("parseCCache(v3) unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, wantCreds) {
			t.Fatalf("parseCCache(v3) = %+v, want %+v", got, wantCreds)
		}
	})

	t.Run("v4_full_fixture", func(t *testing.T) {
		raw := bytes.Join([][]byte{
			mitMarshalV4Header,
			mitMarshalV4Princ,
			mitMarshalV4Cred1,
			mitMarshalV4Cred2,
		}, nil)
		got, err := parseCCache(raw)
		if err != nil {
			t.Fatalf("parseCCache(v4) unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, wantCreds) {
			t.Fatalf("parseCCache(v4) = %+v, want %+v", got, wantCreds)
		}
	})

	t.Run("v1_unsupported", func(t *testing.T) {
		raw := bytes.Join([][]byte{
			mitMarshalV1Header,
			mitMarshalV1Princ,
			mitMarshalV1Cred1,
			mitMarshalV1Cred2,
		}, nil)
		if _, err := parseCCache(raw); err == nil {
			t.Fatal("parseCCache(v1) succeeded, want error")
		}
	})

	t.Run("v2_unsupported", func(t *testing.T) {
		raw := bytes.Join([][]byte{
			mitMarshalV2Header,
			mitMarshalV2Princ,
			mitMarshalV2Cred1,
			mitMarshalV2Cred2,
		}, nil)
		if _, err := parseCCache(raw); err == nil {
			t.Fatal("parseCCache(v2) succeeded, want error")
		}
	})
}

// TestParseCCacheMITMultiCredOrder ports the multi-component credential and
// iteration-order tests from MIT krb5 src/lib/krb5/ccache/t_cc.c
// (init_structs, init_test_cred, test_order) and verifies that soft-removed
// FILE-ccache credentials (cc_file.c:delete_cred) remain discoverable.
func TestParseCCacheMITMultiCredOrder(t *testing.T) {
	clientPrinc := buildCCachePrinc(1, "REALM", "client-comp1", "client-comp2")
	serverPrinc1 := buildCCachePrinc(1, "REALM", "server-comp1", "server-comp2")
	serverPrinc2 := buildCCachePrinc(1, "REALM", "server-comp1", "server-comp3")

	baseSpec := testCCacheCredSpec{
		client:      clientPrinc,
		server:      serverPrinc1,
		enctype:     1,
		key:         []byte("1"),
		authTime:    1111,
		startTime:   2222,
		endTime:     3333,
		renewTill:   4444,
		isSKey:      1,
		ticketFlags: 5555,
		addrs: []testCCacheAddr{
			{addrType: 2, data: []byte{0x00, 0x01, 0x23, 0x45}},
		},
		authData: []testCCacheAuthData{
			{adType: 1, data: []byte{5}},
			{adType: 4, data: []byte{4, 6}},
		},
		ticket:       []byte("This is ticket 1\x00"),
		secondTicket: []byte("This is ticket 2\x00"),
	}
	spec2 := baseSpec
	spec2.server = serverPrinc2

	want := []ccacheCredential{
		{
			ClientPrincipal: "client-comp1/client-comp2",
			ClientRealm:     "REALM",
			ServerPrincipal: "server-comp1/server-comp2",
			StartTime:       time.Unix(2222, 0),
			EndTime:         time.Unix(3333, 0),
			RenewTill:       time.Unix(4444, 0),
		},
		{
			ClientPrincipal: "client-comp1/client-comp2",
			ClientRealm:     "REALM",
			ServerPrincipal: "server-comp1/server-comp3",
			StartTime:       time.Unix(2222, 0),
			EndTime:         time.Unix(3333, 0),
			RenewTill:       time.Unix(4444, 0),
		},
	}

	for _, version := range []uint16{0x0503, 0x0504} {
		name := "v3"
		hdr := []byte("\x05\x03")
		if version == 0x0504 {
			name = "v4"
			hdr = []byte("\x05\x04\x00\x00")
		}
		t.Run(name+"_order_preserved", func(t *testing.T) {
			raw := bytes.Join([][]byte{
				hdr,
				clientPrinc,
				buildCCacheCred(version, baseSpec),
				buildCCacheCred(version, spec2),
			}, nil)
			got, err := parseCCache(raw)
			if err != nil {
				t.Fatalf("parseCCache(%s) unexpected error: %v", name, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parseCCache(%s) = %+v, want %+v", name, got, want)
			}
		})
	}

	t.Run("soft_removed_renewable_tgt_retained", func(t *testing.T) {
		// cc_file.c:delete_cred overwrites endtime=0 and authtime=-1 (0xFFFFFFFF)
		// in place while leaving the keyblock, ASN.1 ticket bytes, and renew_till
		// untouched on disk. parseCCache returns raw on-disk entries without
		// filtering delete_cred tombstones; expiration is enforced by emitTicketCache.
		removedTGT := baseSpec
		removedTGT.server = buildCCachePrinc(2, "REALM", "krbtgt", "REALM")
		removedTGT.authTime = 0xFFFFFFFF
		removedTGT.endTime = 0
		removedTGT.renewTill = 1900000000

		raw := bytes.Join([][]byte{
			[]byte("\x05\x04\x00\x00"),
			clientPrinc,
			buildCCacheCred(0x0504, removedTGT),
		}, nil)
		got, err := parseCCache(raw)
		if err != nil {
			t.Fatalf("parseCCache(soft_removed) unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ServerPrincipal != "krbtgt/REALM" ||
			!got[0].EndTime.Equal(time.Unix(0, 0)) ||
			!got[0].RenewTill.Equal(time.Unix(1900000000, 0)) {
			t.Fatalf("parseCCache(soft_removed) = %+v", got)
		}
	})
}

// TestParseCCacheMITConfigEntries ports credential cache configuration entry tests
// from MIT krb5 src/lib/krb5/krb/t_cc_config.c, src/lib/krb5/ccache/ccfns.c, and
// doc/formats/ccache_file_format.rst (X-CACHECONF: and X-RMED-CONF: entries).
func TestParseCCacheMITConfigEntries(t *testing.T) {
	defaultPrinc := buildCCachePrinc(1, "KRBTEST.COM", "alice")

	// 2-component config entry (e.g. fast_avail = "yes")
	confFastAvail := testCCacheCredSpec{
		client: defaultPrinc,
		server: buildCCachePrinc(0, "X-CACHECONF:", "krb5_ccache_conf_data", "fast_avail"),
		ticket: []byte("yes"),
	}
	// 3-component config entry associated with a server principal (e.g. pa_type = "2")
	confPAType := testCCacheCredSpec{
		client: defaultPrinc,
		server: buildCCachePrinc(0, "X-CACHECONF:", "krb5_ccache_conf_data", "pa_type", "krbtgt/KRBTEST.COM@KRBTEST.COM"),
		ticket: []byte("2"),
	}
	// Soft-deleted config entry (cc_file.c:1065 replaces "X-CACHECONF:" with "X-RMED-CONF:")
	confRemoved := testCCacheCredSpec{
		client:   defaultPrinc,
		server:   buildCCachePrinc(0, "X-RMED-CONF:", "krb5_ccache_conf_data", "pa_config_data"),
		authTime: 0xFFFFFFFF,
		ticket:   []byte(`{"challenge":"ok"}`),
	}
	// Active TGT following the config entries
	activeTGT := testCCacheCredSpec{
		client:    defaultPrinc,
		server:    buildCCachePrinc(2, "KRBTEST.COM", "krbtgt", "KRBTEST.COM"),
		enctype:   18,
		key:       bytes.Repeat([]byte{0x42}, 32),
		authTime:  1700000000,
		startTime: 1700000000,
		endTime:   1700036000,
		renewTill: 1700604800,
		ticket:    []byte("asn1-tgt-bytes"),
	}

	raw := bytes.Join([][]byte{
		mitMarshalV4Header,
		defaultPrinc,
		buildCCacheCred(0x0504, confFastAvail),
		buildCCacheCred(0x0504, confPAType),
		buildCCacheCred(0x0504, confRemoved),
		buildCCacheCred(0x0504, activeTGT),
	}, nil)

	got, err := parseCCache(raw)
	if err != nil {
		t.Fatalf("parseCCache(config_entries) unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("parseCCache(config_entries) returned %d creds, want 4", len(got))
	}
	if got[0].ServerPrincipal != "krb5_ccache_conf_data/fast_avail" {
		t.Fatalf("got[0].ServerPrincipal = %q", got[0].ServerPrincipal)
	}
	if got[1].ServerPrincipal != "krb5_ccache_conf_data/pa_type/krbtgt/KRBTEST.COM@KRBTEST.COM" {
		t.Fatalf("got[1].ServerPrincipal = %q", got[1].ServerPrincipal)
	}
	if got[3].ServerPrincipal != "krbtgt/KRBTEST.COM" ||
		got[3].ClientPrincipal != "alice" ||
		got[3].ClientRealm != "KRBTEST.COM" {
		t.Fatalf("got[3] (TGT) = %+v", got[3])
	}
}

// TestParseCCacheMITY2038Timestamps ports the post-2038 unsigned timestamp handling
// from MIT krb5 src/tests/t_y2038.py and src/include/k5-int.h:ts2tt.
func TestParseCCacheMITY2038Timestamps(t *testing.T) {
	princ := buildCCachePrinc(1, "KRBTEST.COM", "user")
	const (
		tsY2038Boundary = uint32(0x80000000) // 2038-01-19T03:14:08Z
		tsY2040         = uint32(2211840000) // 2040-02-02T00:00:00Z (t_y2038.py:54)
		tsMaxUint32     = uint32(0xFFFFFFFF) // 2106-02-07T06:28:15Z
	)
	cred := buildCCacheCred(0x0504, testCCacheCredSpec{
		client:    princ,
		server:    buildCCachePrinc(2, "KRBTEST.COM", "krbtgt", "KRBTEST.COM"),
		enctype:   18,
		key:       []byte{1, 2, 3, 4},
		authTime:  tsY2038Boundary,
		startTime: tsY2038Boundary,
		endTime:   tsY2040,
		renewTill: tsMaxUint32,
		ticket:    []byte("tkt"),
	})
	raw := bytes.Join([][]byte{[]byte("\x05\x04\x00\x00"), princ, cred}, nil)

	got, err := parseCCache(raw)
	if err != nil {
		t.Fatalf("parseCCache(y2038) unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parseCCache(y2038) len = %d, want 1", len(got))
	}
	if !got[0].StartTime.Equal(time.Unix(int64(tsY2038Boundary), 0)) {
		t.Fatalf("StartTime = %v, want %v", got[0].StartTime.UTC(), time.Unix(int64(tsY2038Boundary), 0).UTC())
	}
	if !got[0].EndTime.Equal(time.Unix(int64(tsY2040), 0)) {
		t.Fatalf("EndTime = %v, want %v", got[0].EndTime.UTC(), time.Unix(int64(tsY2040), 0).UTC())
	}
	if !got[0].RenewTill.Equal(time.Unix(int64(tsMaxUint32), 0)) {
		t.Fatalf("RenewTill = %v, want %v", got[0].RenewTill.UTC(), time.Unix(int64(tsMaxUint32), 0).UTC())
	}
}

// TestParseCCacheMITFuzzSeeds runs the exact seed corpus files from
// MIT krb5 src/tests/fuzzing/fuzz_ccache_seed_corpus/*.
func TestParseCCacheMITFuzzSeeds(t *testing.T) {
	t.Run("v4_principal_only", func(t *testing.T) {
		got, err := parseCCache(mitFuzzCCacheV4PrincipalOnly)
		if err != nil {
			t.Fatalf("parseCCache(v4_principal_only) unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("parseCCache(v4_principal_only) = %+v, want empty", got)
		}
	})

	t.Run("v1_principal_only_unsupported", func(t *testing.T) {
		if _, err := parseCCache(mitFuzzCCacheV1PrincipalOnly); err == nil {
			t.Fatal("parseCCache(v1_principal_only) succeeded, want error")
		}
	})
}

// TestParseCCacheV4Headers tests v4 header tag parsing and error rules from
// MIT krb5 src/lib/krb5/ccache/cc_file.c:read_header and doc/formats/ccache_file_format.rst.
func TestParseCCacheV4Headers(t *testing.T) {
	t.Run("empty_v4_header", func(t *testing.T) {
		raw := append([]byte("\x05\x04\x00\x00"), mitMarshalV4Princ...)
		got, err := parseCCache(raw)
		if err != nil || len(got) != 0 {
			t.Fatalf("parseCCache(empty_v4_header) = (%+v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("multiple_unknown_and_deltatime_tags", func(t *testing.T) {
		// doc/formats/ccache_file_format.rst: "A file format implementation
		// should ignore fields with unknown tags."
		hdrFields := bytes.Join([][]byte{
			// Tag 1 (FCC_TAG_DELTATIME), len 8
			[]byte("\x00\x01\x00\x08\x00\x00\x01\x2C\x00\x00\xD4\x31"),
			// Unknown tag 99, len 3
			[]byte("\x00\x63\x00\x03abc"),
			// Unknown tag 255, len 0
			[]byte("\x00\xff\x00\x00"),
		}, nil)
		var hdr bytes.Buffer
		hdr.Write([]byte("\x05\x04"))
		_ = binary.Write(&hdr, binary.BigEndian, uint16(len(hdrFields)))
		hdr.Write(hdrFields)
		hdr.Write(mitMarshalV4Princ)
		hdr.Write(mitMarshalV4Cred1)

		got, err := parseCCache(hdr.Bytes())
		if err != nil || len(got) != 1 || got[0].ServerPrincipal != "test/host" {
			t.Fatalf("parseCCache(multiple_tags) = (%+v, %v)", got, err)
		}
	})

	malformedHeaders := []struct {
		name string
		data []byte
	}{
		{
			name: "missing_header_length",
			data: []byte("\x05\x04"),
		},
		{
			name: "truncated_header_length_1_byte",
			data: []byte("\x05\x04\x00"),
		},
		{
			name: "header_length_exceeds_file",
			data: []byte("\x05\x04\x00\x10\x00\x01\x00\x08"),
		},
		{
			name: "header_trailing_1_byte_cannot_fit_tag",
			data: append([]byte("\x05\x04\x00\x01\x00"), mitMarshalV4Princ...),
		},
		{
			name: "header_trailing_3_bytes_cannot_fit_tag_and_len",
			data: append([]byte("\x05\x04\x00\x03\x00\x01\x00"), mitMarshalV4Princ...),
		},
		{
			name: "tag_length_overflows_remaining_header",
			data: append([]byte("\x05\x04\x00\x06\x00\x01\x00\x08\x00\x00"), mitMarshalV4Princ...),
		},
	}

	for _, tc := range malformedHeaders {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCCache(tc.data); err == nil {
				t.Fatalf("parseCCache(%s) succeeded, want error", tc.name)
			}
		})
	}
}

// TestParseCCacheMalformed covers truncation at every field boundary of a
// credential and bogus length/count values from MIT krb5 ccmarshal.c & cc_file.c.
func TestParseCCacheMalformed(t *testing.T) {
	// Every prefix of a valid v3 and v4 single-cred cache strictly shorter than
	// the full cache (except the boundary right after the default principal,
	// where 0 credentials is valid) must return a parse error.
	t.Run("every_truncation_offset_v3", func(t *testing.T) {
		headerAndPrincLen := len(mitMarshalV3Header) + len(mitMarshalV3Princ)
		full := bytes.Join([][]byte{mitMarshalV3Header, mitMarshalV3Princ, mitMarshalV3Cred1}, nil)
		for cut := 0; cut < len(full); cut++ {
			if cut == headerAndPrincLen {
				continue // valid 0-cred ccache
			}
			if _, err := parseCCache(full[:cut]); err == nil {
				t.Fatalf("parseCCache(v3[:%d]) succeeded on truncated buffer, want error", cut)
			}
		}
	})

	t.Run("every_truncation_offset_v4", func(t *testing.T) {
		headerAndPrincLen := len(mitMarshalV4Header) + len(mitMarshalV4Princ)
		full := bytes.Join([][]byte{mitMarshalV4Header, mitMarshalV4Princ, mitMarshalV4Cred1}, nil)
		for cut := 0; cut < len(full); cut++ {
			if cut == headerAndPrincLen {
				continue // valid 0-cred ccache
			}
			if _, err := parseCCache(full[:cut]); err == nil {
				t.Fatalf("parseCCache(v4[:%d]) succeeded on truncated buffer, want error", cut)
			}
		}
	})

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty_input",
			data: nil,
		},
		{
			name: "one_byte_header",
			data: []byte{0x05},
		},
		{
			name: "version_0500_invalid",
			data: []byte("\x05\x00"),
		},
		{
			name: "version_0505_invalid",
			data: []byte("\x05\x05"),
		},
		{
			name: "version_0404_invalid",
			data: []byte("\x04\x04"),
		},
		{
			// ccmarshal.c:175 sanity check: ncomps > in->len
			name: "default_princ_huge_component_count",
			data: []byte("\x05\x03\x00\x00\x00\x01\x7f\xff\xff\xff\x00\x00\x00\x05REALM"),
		},
		{
			name: "default_princ_negative_int32_component_count",
			data: []byte("\x05\x03\x00\x00\x00\x01\x80\x00\x00\x00\x00\x00\x00\x05REALM"),
		},
		{
			name: "default_princ_uint32_max_realm_length",
			data: []byte("\x05\x03\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff\xff\xffREALM"),
		},
		{
			// ccmarshal.c:232 sanity check: address count > in->len
			name: "cred_uint32_max_address_count",
			data: func() []byte {
				var b bytes.Buffer
				b.Write([]byte("\x05\x04\x00\x00"))
				b.Write(mitMarshalV4Princ)
				b.Write(mitMarshalV4Princ) // client
				b.Write(mitMarshalV4Princ) // server
				b.Write([]byte("\x00\x11\x00\x00\x00\x01k"))
				b.Write(make([]byte, 4*4+1+4)) // times + is_skey + flags
				_ = binary.Write(&b, binary.BigEndian, uint32(math.MaxUint32))
				return b.Bytes()
			}(),
		},
		{
			// ccmarshal.c:269 sanity check: authdata count > in->len
			name: "cred_uint32_max_authdata_count",
			data: func() []byte {
				var b bytes.Buffer
				b.Write([]byte("\x05\x04\x00\x00"))
				b.Write(mitMarshalV4Princ)
				b.Write(mitMarshalV4Princ) // client
				b.Write(mitMarshalV4Princ) // server
				b.Write([]byte("\x00\x11\x00\x00\x00\x01k"))
				b.Write(make([]byte, 4*4+1+4))                    // times + is_skey + flags
				_ = binary.Write(&b, binary.BigEndian, uint32(0)) // 0 addrs
				_ = binary.Write(&b, binary.BigEndian, uint32(math.MaxUint32))
				return b.Bytes()
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCCache(tc.data); err == nil {
				t.Fatalf("parseCCache(%s) succeeded, want error", tc.name)
			}
		})
	}
}

// TestParseCCachePartialRecovery verifies that credentials parsed before a
// truncated trailing credential are still returned alongside the error.
func TestParseCCachePartialRecovery(t *testing.T) {
	raw := bytes.Join([][]byte{
		mitMarshalV4Header,
		mitMarshalV4Princ,
		mitMarshalV4Cred1,
		mitMarshalV4Cred2[:20], // truncated second cred
	}, nil)

	got, err := parseCCache(raw)
	if err == nil {
		t.Fatal("parseCCache() succeeded on truncated second cred, want error")
	}
	if len(got) != 1 || got[0].ClientPrincipal != "testclient" || got[0].ServerPrincipal != "test/host" {
		t.Fatalf("parseCCache() partial creds = %+v", got)
	}
}

// TestLoadKeytabAndCCache exercises the file-reading entry points loadKeytab
// and loadCCache with temporary files on a local mount.
func TestLoadKeytabAndCCache(t *testing.T) {
	setTestFSGuard(t, false, []mountEntry{{mountPoint: "/", fsType: "ext4"}})
	tmp := t.TempDir()

	t.Run("loadKeytab_valid", func(t *testing.T) {
		p := filepath.Join(tmp, "krb5.keytab")
		if err := os.WriteFile(p, mitFuzzKeytabV502OneEntry, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadKeytab(context.Background(), p)
		if err != nil {
			t.Fatalf("loadKeytab() unexpected error: %v", err)
		}
		want := []keytabEntry{{Principal: "user@REALM", Realm: "REALM"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("loadKeytab() = %+v, want %+v", got, want)
		}
	})

	t.Run("loadKeytab_empty_file_errors", func(t *testing.T) {
		p := filepath.Join(tmp, "empty.keytab")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadKeytab(context.Background(), p); err == nil {
			t.Fatal("loadKeytab(empty) succeeded, want error")
		}
	})

	t.Run("loadCCache_valid", func(t *testing.T) {
		p := filepath.Join(tmp, "krb5cc_1000")
		raw := bytes.Join([][]byte{mitMarshalV4Header, mitMarshalV4Princ, mitMarshalV4Cred1}, nil)
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadCCache(context.Background(), p)
		if err != nil {
			t.Fatalf("loadCCache() unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ClientPrincipal != "testclient" {
			t.Fatalf("loadCCache() = %+v", got)
		}
	})

	t.Run("loadCCache_empty_file_returns_nil_nil", func(t *testing.T) {
		p := filepath.Join(tmp, "krb5cc_empty")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadCCache(context.Background(), p)
		if err != nil || got != nil {
			t.Fatalf("loadCCache(empty) = (%+v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("nonexistent_file", func(t *testing.T) {
		p := filepath.Join(tmp, "does_not_exist")
		if _, err := loadKeytab(context.Background(), p); err == nil {
			t.Fatal("loadKeytab(nonexistent) succeeded, want error")
		}
		if _, err := loadCCache(context.Background(), p); err == nil {
			t.Fatal("loadCCache(nonexistent) succeeded, want error")
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		p := filepath.Join(tmp, "krb5.keytab")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := loadKeytab(ctx, p); err == nil {
			t.Fatal("loadKeytab(canceled) succeeded, want error")
		}
		if _, err := loadCCache(ctx, p); err == nil {
			t.Fatal("loadCCache(canceled) succeeded, want error")
		}
	})
}

// TestPrincipalToBloodhoundNameEmptyGuards ensures empty principals or realms
// from 0-component ccache entries (such as t_marshal.c cred2) are rejected by
// PrincipalToBloodhoundName rather than producing malformed node names.
func TestPrincipalToBloodhoundNameEmptyGuards(t *testing.T) {
	for _, tc := range []struct {
		principal string
		realm     string
	}{
		{"", ""},
		{"", "KRBTEST.COM"},
		{"user", ""},
		{"@KRBTEST.COM", "KRBTEST.COM"},
	} {
		if got, err := PrincipalToBloodhoundName(tc.principal, tc.realm); err == nil {
			t.Fatalf("PrincipalToBloodhoundName(%q, %q) = %q, want error", tc.principal, tc.realm, got)
		}
	}
}

type marshaledEdge struct {
	Kind string `json:"kind"`
	End  struct {
		Kind             string `json:"kind"`
		PropertyMatchers []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"property_matchers"`
	} `json:"end"`
	Properties map[string]any `json:"properties"`
}

func unmarshalTestEdges(t *testing.T, b *opengraph.GraphBuilder) []marshaledEdge {
	t.Helper()
	var env struct {
		Graph struct {
			Edges []marshaledEdge `json:"edges"`
		} `json:"graph"`
	}
	if err := json.Unmarshal([]byte(b.Marshal()), &env); err != nil {
		t.Fatalf("json.Unmarshal(b.Marshal()): %v", err)
	}
	return env.Graph.Edges
}

func newLocalTestHost(t *testing.T, homeDir string) *Host {
	t.Helper()
	uid := strconv.Itoa(os.Getuid())
	return &Host{
		uniqueId: "host1",
		FQDN:     "host1.local",
		Users: map[string]*User{
			uid: {UserName: "localuser", UID: uid, HomeDir: homeDir, Shell: "/bin/bash"},
		},
		referencedUsers: make(map[string]struct{}),
	}
}

func TestEmitTicketCacheKRBTGTCaseInsensitive(t *testing.T) {
	setTestFSGuard(t, false, []mountEntry{{mountPoint: "/", fsType: "ext4"}})
	tmp := t.TempDir()
	now := time.Unix(1700000000, 0)
	validEnd := uint32(now.Add(time.Hour).Unix())

	makeCred := func(client string, serverComps ...string) []byte {
		return buildCCacheCred(0x0504, testCCacheCredSpec{
			client:    buildCCachePrinc(1, "KRBTEST.COM", client),
			server:    buildCCachePrinc(2, "KRBTEST.COM", serverComps...),
			enctype:   18,
			key:       []byte{1, 2, 3, 4},
			authTime:  uint32(now.Unix()),
			startTime: uint32(now.Unix()),
			endTime:   validEnd,
			ticket:    []byte("tkt"),
		})
	}

	defaultPrinc := buildCCachePrinc(1, "KRBTEST.COM", "alice")
	confEntry := buildCCacheCred(0x0504, testCCacheCredSpec{
		client: defaultPrinc,
		server: buildCCachePrinc(0, "X-CACHECONF:", "krb5_ccache_conf_data", "fast_avail"),
		ticket: []byte("yes"),
	})

	raw := bytes.Join([][]byte{
		[]byte("\x05\x04\x00\x00"),
		defaultPrinc,
		makeCred("alice", "krbtgt", "KRBTEST.COM"),
		makeCred("bob", "KRBTGT", "KRBTEST.COM"),
		makeCred("carol", "KrBtGt", "KRBTEST.COM"),
		makeCred("dave", "cifs", "dc01.krbtest.com"),
		makeCred("eve", "krbtgt"),
		makeCred("frank", "krbtgt", ""),
		confEntry,
	}, nil)

	cachePath := filepath.Join(tmp, "krb5cc_test")
	if err := os.WriteFile(cachePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	h := newLocalTestHost(t, tmp)
	b := opengraph.NewGraphBuilder()
	if err := emitTicketCache(context.Background(), h, b, cachePath, now); err != nil {
		t.Fatalf("emitTicketCache() unexpected error: %v", err)
	}

	edges := unmarshalTestEdges(t, b)
	var gotNames []string
	for _, e := range edges {
		if e.Kind != "GLH_HasTGT" || len(e.End.PropertyMatchers) != 1 {
			t.Fatalf("unexpected edge: %+v", e)
		}
		gotNames = append(gotNames, e.End.PropertyMatchers[0].Value)
	}
	wantNames := []string{"ALICE@KRBTEST.COM", "BOB@KRBTEST.COM", "CAROL@KRBTEST.COM"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("emitted HasTGT targets = %v, want %v", gotNames, wantNames)
	}
}

func TestEmitTicketCacheExpiration(t *testing.T) {
	setTestFSGuard(t, false, []mountEntry{{mountPoint: "/", fsType: "ext4"}})
	tmp := t.TempDir()
	now := time.Unix(1700000000, 0)
	tNow := uint32(now.Unix())

	makeTGT := func(client string, endTime, renewTill uint32) []byte {
		return buildCCacheCred(0x0504, testCCacheCredSpec{
			client:    buildCCachePrinc(1, "KRBTEST.COM", client),
			server:    buildCCachePrinc(2, "KRBTEST.COM", "krbtgt", "KRBTEST.COM"),
			enctype:   18,
			key:       []byte{1, 2, 3, 4},
			authTime:  tNow - 3600,
			startTime: tNow - 3600,
			endTime:   endTime,
			renewTill: renewTill,
			ticket:    []byte("tkt"),
		})
	}

	defaultPrinc := buildCCachePrinc(1, "KRBTEST.COM", "valid_nonrenew")
	raw := bytes.Join([][]byte{
		[]byte("\x05\x04\x00\x00"),
		defaultPrinc,
		makeTGT("valid_nonrenew", tNow+3600, 0),
		makeTGT("valid_boundary", tNow, 0),
		makeTGT("valid_renewable", tNow+3600, tNow+86400),
		makeTGT("expired_future_renew", tNow-1, tNow+86400),
		makeTGT("expired_nonrenew", tNow-3600, 0),
		makeTGT("soft_removed_tombstone", 0, tNow+86400),
	}, nil)

	cachePath := filepath.Join(tmp, "krb5cc_exp")
	if err := os.WriteFile(cachePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	h := newLocalTestHost(t, tmp)
	b := opengraph.NewGraphBuilder()
	if err := emitTicketCache(context.Background(), h, b, cachePath, now); err != nil {
		t.Fatalf("emitTicketCache() unexpected error: %v", err)
	}

	edges := unmarshalTestEdges(t, b)
	var gotNames []string
	for _, e := range edges {
		if e.Kind != "GLH_HasTGT" || len(e.End.PropertyMatchers) != 1 {
			t.Fatalf("unexpected edge: %+v", e)
		}
		gotNames = append(gotNames, e.End.PropertyMatchers[0].Value)
	}
	wantNames := []string{
		"VALID_NONRENEW@KRBTEST.COM",
		"VALID_BOUNDARY@KRBTEST.COM",
		"VALID_RENEWABLE@KRBTEST.COM",
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("emitted HasTGT targets = %v, want %v", gotNames, wantNames)
	}
}

// FuzzParseKeytab ports MIT krb5 src/tests/fuzzing/fuzz_keytab.c along with all
// seeds from src/tests/fuzzing/fuzz_keytab_seed_corpus/* and src/tests/t_keytab.py.
func FuzzParseKeytab(f *testing.F) {
	record := mitTKeytabPyBaseRecord()
	f.Add(mitFuzzKeytabV502OneEntry)
	f.Add(mitFuzzKeytabVersionOnly)
	f.Add(mitFuzzKeytabVersion0x501)
	f.Add(mitFuzzKeytabBigSizeV1)
	f.Add(appendKeytabRecord([]byte("\x05\x02"), int32(len(record)), record))
	f.Add(appendKeytabRecord([]byte("\x05\x02"), int32(len(record)+4), append(bytes.Clone(record), 0, 0, 0, 3)))
	f.Add([]byte("\x05\x02\x80\x00\x00\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseKeytab(data)
	})
}

// FuzzParseCCache ports MIT krb5 src/tests/fuzzing/fuzz_ccache.c,
// fuzz_marshal_cred.c, and fuzz_marshal_princ.c along with their seed corpora.
func FuzzParseCCache(f *testing.F) {
	f.Add(mitFuzzCCacheV1PrincipalOnly)
	f.Add(mitFuzzCCacheV4PrincipalOnly)
	f.Add(bytes.Join([][]byte{mitMarshalV3Header, mitMarshalV3Princ, mitMarshalV3Cred1, mitMarshalV3Cred2}, nil))
	f.Add(bytes.Join([][]byte{mitMarshalV4Header, mitMarshalV4Princ, mitMarshalV4Cred1, mitMarshalV4Cred2}, nil))
	// fuzz_marshal_princ_seed_corpus/princ_input_4.bin wrapped in a v4 header
	f.Add(append([]byte("\x05\x04\x00\x00"), mitMarshalV4Princ...))
	// fuzz_marshal_cred_seed_corpus/cred_1_input_4.bin & cred_2_input_4.bin wrapped in a v4 header + princ
	f.Add(bytes.Join([][]byte{[]byte("\x05\x04\x00\x00"), mitMarshalV4Princ, mitMarshalV4Cred1}, nil))
	f.Add(bytes.Join([][]byte{[]byte("\x05\x04\x00\x00"), mitMarshalV4Princ, mitMarshalV4Cred2}, nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCCache(data)
	})
}
