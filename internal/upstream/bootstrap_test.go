package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/logging"
)

func TestBootstrapFailoverPromotesSuccessfulIP(t *testing.T) {
	targets, err := newBootstrapDialTargets("resolver.test", "853", []net.IP{
		net.ParseIP("192.0.2.10"),
		net.ParseIP("192.0.2.20"),
	}, "failover")
	if err != nil {
		t.Fatalf("newBootstrapDialTargets() error = %v", err)
	}

	attempts := make([]string, 0, 3)
	conn, err := targets.dialContext(context.Background(), "tcp", func(ctx context.Context, network, addr string) (net.Conn, error) {
		attempts = append(attempts, addr)
		if addr == "192.0.2.10:853" {
			return nil, context.DeadlineExceeded
		}
		client, server := net.Pipe()
		go server.Close()
		return client, nil
	})
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	_ = conn.Close()

	if len(attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(attempts))
	}
	if got := targets.snapshot()[0]; got != "192.0.2.20:853" {
		t.Fatalf("promoted address = %s, want 192.0.2.20:853", got)
	}
}

func TestBootstrapRoundRobinRotatesStartingAddress(t *testing.T) {
	targets, err := newBootstrapDialTargets("resolver.test", "853", []net.IP{
		net.ParseIP("192.0.2.10"),
		net.ParseIP("192.0.2.20"),
	}, "round_robin")
	if err != nil {
		t.Fatalf("newBootstrapDialTargets() error = %v", err)
	}

	var attempts []string
	for i := 0; i < 2; i++ {
		conn, err := targets.dialContext(context.Background(), "tcp", func(ctx context.Context, network, addr string) (net.Conn, error) {
			attempts = append(attempts, addr)
			client, server := net.Pipe()
			go server.Close()
			return client, nil
		})
		if err != nil {
			t.Fatalf("dialContext() error = %v", err)
		}
		_ = conn.Close()
	}

	if len(attempts) != 2 {
		t.Fatalf("attempt count = %d, want 2", len(attempts))
	}
	if attempts[0] == attempts[1] {
		t.Fatalf("round robin did not rotate: %v", attempts)
	}
}

func TestRaceDialClosesLosers(t *testing.T) {
	type fakeConn struct {
		id string
	}

	var closed atomic.Int32
	conn, addr, err := raceDial(context.Background(), []string{"a", "b", "c"}, func(ctx context.Context, target string) (*fakeConn, error) {
		switch target {
		case "a":
			time.Sleep(20 * time.Millisecond)
		case "b":
			time.Sleep(5 * time.Millisecond)
		case "c":
			time.Sleep(15 * time.Millisecond)
		}
		return &fakeConn{id: target}, nil
	}, func(conn *fakeConn) {
		closed.Add(1)
	})
	if err != nil {
		t.Fatalf("raceDial() error = %v", err)
	}
	if addr != "b" {
		t.Fatalf("winner = %s, want b", addr)
	}
	if conn.id != "b" {
		t.Fatalf("winner conn id = %s, want b", conn.id)
	}
	time.Sleep(30 * time.Millisecond)
	if got := closed.Load(); got != 2 {
		t.Fatalf("closed losers = %d, want 2", got)
	}
}

func TestBuildManagerRejectsInvalidBootstrapProgrammaticConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Upstreams = []config.UpstreamConfig{{
		URL:       "https://resolver.test/dns-query",
		Bootstrap: config.BootstrapIPs{nil},
	}}

	if _, _, err := BuildManager(cfg, logging.New(logging.Level("error")), nil); err == nil {
		t.Fatal("BuildManager() succeeded, want error")
	}
}

func TestDoHBootstrapPreservesHostAndSNI(t *testing.T) {
	tlsConf, serverName := testTLSConfig(t, "resolver.test")

	var hostHeader atomic.Value
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		hostHeader.Store(r.Host)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			t.Fatalf("Unpack() error = %v", err)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(127, 0, 0, 1)},
		}
		packed, err := resp.Pack()
		if err != nil {
			t.Fatalf("Pack() error = %v", err)
		}
		w.Header().Set("content-type", "application/dns-message")
		_, _ = w.Write(packed)
	})
	httpSrv := &http.Server{Handler: mux}
	defer httpSrv.Shutdown(context.Background())
	go func() {
		_ = httpSrv.Serve(ln)
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	cfg := config.Default()
	cfg.InsecureTLS = true
	cfg.HealthChecks.Enabled = false
	cfg.Upstreams = []config.UpstreamConfig{{
		URL:       "https://resolver.test:" + strconv.Itoa(port) + "/dns-query",
		Bootstrap: config.BootstrapIPs{net.ParseIP("127.0.0.1")},
	}}

	mgr, _, err := BuildManager(cfg, logging.New(logging.Level("error")), nil)
	if err != nil {
		t.Fatalf("BuildManager() error = %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	resp, err := mgr.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Resolve() rcode = %d, want NOERROR", resp.Rcode)
	}
	if got, _ := hostHeader.Load().(string); got != "resolver.test:"+strconv.Itoa(port) {
		t.Fatalf("host header = %q, want resolver.test:%d", got, port)
	}
	if got, _ := serverName.Load().(string); got != "resolver.test" {
		t.Fatalf("SNI = %q, want resolver.test", got)
	}
}

func TestTLSFactoryUsesBootstrapIPAndSNI(t *testing.T) {
	tlsConf, serverName := testTLSConfig(t, "resolver.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()

	targets, err := newBootstrapDialTargets("resolver.test", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), []net.IP{net.ParseIP("127.0.0.1")}, "failover")
	if err != nil {
		t.Fatalf("newBootstrapDialTargets() error = %v", err)
	}
	factory := MakeTLSFactory(targets, &tls.Config{InsecureSkipVerify: true}, &net.Dialer{Timeout: time.Second})

	conn, err := factory(context.Background())
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	_ = conn.Close()
	<-done

	if got, _ := serverName.Load().(string); got != "resolver.test" {
		t.Fatalf("SNI = %q, want resolver.test", got)
	}
}

func TestDoQBuildAndDialUseBootstrapAndServerName(t *testing.T) {
	tlsConf, serverName := testTLSConfig(t, "resolver.test")
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", tlsConf, &quic.Config{})
	if err != nil {
		t.Fatalf("ListenAddrEarly() error = %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		req, err := readDoQMessage(stream)
		if err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		_ = writeDoQMessage(stream, resp)
		_ = stream.Close()
	}()

	addr := listener.Addr().(*net.UDPAddr)
	cfg := config.Default()
	cfg.InsecureTLS = true
	cfg.HealthChecks.Enabled = false
	cfg.PrewarmPools = false
	cfg.Upstreams = []config.UpstreamConfig{{
		URL:       "quic://resolver.test:" + strconv.Itoa(addr.Port),
		Bootstrap: config.BootstrapIPs{net.ParseIP("127.0.0.1")},
	}}

	mgr, _, err := BuildManager(cfg, logging.New(logging.Level("error")), nil)
	if err != nil {
		t.Fatalf("BuildManager() error = %v", err)
	}
	doqUp, ok := mgr.upstreams[0].(*DoQ)
	if !ok {
		t.Fatalf("upstream type = %T, want *DoQ", mgr.upstreams[0])
	}
	if doqUp.tlsConf.ServerName != "resolver.test" {
		t.Fatalf("tls server name = %q, want resolver.test", doqUp.tlsConf.ServerName)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	resp, err := doqUp.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	<-done

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Exchange() rcode = %d, want NOERROR", resp.Rcode)
	}
	if got, _ := serverName.Load().(string); got != "resolver.test" {
		t.Fatalf("SNI = %q, want resolver.test", got)
	}
}

func testTLSConfig(t *testing.T, serverHost string) (*tls.Config, *atomic.Value) {
	t.Helper()

	certPEM, keyPEM := testCertificate(t, serverHost)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair() error = %v", err)
	}

	var serverName atomic.Value
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq", "h2", "http/1.1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName.Store(chi.ServerName)
			return nil, nil
		},
	}, &serverName
}

func testCertificate(t *testing.T, serverHost string) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverHost},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
