package upstream

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
)

func TestDoQMessageRoundTrip(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	msg.Id = 0x1234

	var buf bytes.Buffer
	if err := writeDoQMessage(&buf, msg); err != nil {
		t.Fatalf("writeDoQMessage() error = %v", err)
	}
	raw := buf.Bytes()
	if len(raw) < 2 {
		t.Fatalf("framed output too short: %d", len(raw))
	}
	gotLen := int(binary.BigEndian.Uint16(raw[:2]))
	if gotLen != len(raw)-2 {
		t.Fatalf("length prefix mismatch: got %d want %d", gotLen, len(raw)-2)
	}

	decoded, err := readDoQMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readDoQMessage() error = %v", err)
	}
	gotPacked, err := decoded.Pack()
	if err != nil {
		t.Fatalf("decoded.Pack() error = %v", err)
	}
	wantPacked, err := msg.Pack()
	if err != nil {
		t.Fatalf("msg.Pack() error = %v", err)
	}
	if !bytes.Equal(gotPacked, wantPacked) {
		t.Fatalf("decoded payload mismatch")
	}
}

func TestReadDoQMessageRejectsZeroLength(t *testing.T) {
	_, err := readDoQMessage(bytes.NewReader([]byte{0x00, 0x00}))
	if err == nil {
		t.Fatal("expected error for zero-length DoQ frame")
	}
}

func TestReadDoQMessageRejectsTruncatedPayload(t *testing.T) {
	_, err := readDoQMessage(bytes.NewReader([]byte{0x00, 0x04, 0xde, 0xad}))
	if err == nil {
		t.Fatal("expected error for truncated DoQ payload")
	}
}
