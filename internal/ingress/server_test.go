package ingress

import (
	"net"
	"testing"

	"archuser.org/secure-dns-proxy/internal/logging"
)

func TestStartReturnsBindError(t *testing.T) {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve udp port: %v", err)
	}
	defer udpConn.Close()

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	srv := New("127.0.0.1", port, nil, logging.Default(), nil)

	if err := srv.Start(); err == nil {
		t.Fatalf("expected bind error when UDP port is already in use")
	}
}
