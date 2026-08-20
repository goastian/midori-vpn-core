package masque

import (
	"bytes"
	"net"
	"testing"
)

func TestEncodeDecodeDatagram(t *testing.T) {
	contextID := uint64(42)
	payload := []byte("wireguard-ip-packet-payload-test-data")

	encoded := EncodeDatagram(contextID, payload)
	if len(encoded) <= len(payload) {
		t.Fatalf("expected encoded length > payload length, got %d", len(encoded))
	}

	decoded, err := DecodeDatagram(encoded)
	if err != nil {
		t.Fatalf("failed to decode datagram: %v", err)
	}

	if decoded.ContextID != contextID {
		t.Errorf("expected contextID %d, got %d", contextID, decoded.ContextID)
	}

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("expected payload %s, got %s", payload, decoded.Payload)
	}
}

func TestMASQUESessionManagement(t *testing.T) {
	listener := NewMASQUEListener(Config{
		ListenAddr: ":4433",
		MTU:        1420,
	})

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321}
	assignedIP := net.ParseIP("10.8.0.2")

	sess := listener.RegisterSession("sess-1", remoteAddr, assignedIP)
	if sess == nil {
		t.Fatal("expected session to be created")
	}

	if listener.ActiveSessions() != 1 {
		t.Errorf("expected 1 active session, got %d", listener.ActiveSessions())
	}

	datagram := &IPDatagram{
		ContextID: 0,
		Payload:   []byte("test-ip-traffic"),
	}

	if err := listener.ForwardDatagram("sess-1", datagram); err != nil {
		t.Errorf("failed to forward datagram: %v", err)
	}

	if sess.BytesIn != uint64(len(datagram.Payload)) {
		t.Errorf("expected %d bytes in, got %d", len(datagram.Payload), sess.BytesIn)
	}

	listener.RemoveSession("sess-1")
	if listener.ActiveSessions() != 0 {
		t.Errorf("expected 0 active sessions, got %d", listener.ActiveSessions())
	}
}
