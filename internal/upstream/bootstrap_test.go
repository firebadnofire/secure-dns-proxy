package upstream

import (
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	mrand "math/rand"
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
	targets, err := newAddressSource("resolver.test", "853", "failover", []net.IP{
		net.ParseIP("192.0.2.10"),
		net.ParseIP("192.0.2.20"),
	}, false)
	if err != nil {
		t.Fatalf("newAddressSource() error = %v", err)
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
	if got := targets.snapshot().addrs[0]; got != "192.0.2.20:853" {
		t.Fatalf("promoted address = %s, want 192.0.2.20:853", got)
	}
}

func TestBootstrapRoundRobinRotatesStartingAddress(t *testing.T) {
	targets, err := newAddressSource("resolver.test", "853", "round_robin", []net.IP{
		net.ParseIP("192.0.2.10"),
		net.ParseIP("192.0.2.20"),
	}, false)
	if err != nil {
		t.Fatalf("newAddressSource() error = %v", err)
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

func TestAddressSourceReplaceAdoptsNewAddresses(t *testing.T) {
	targets, err := newAddressSource("resolver.test", "853", "failover", []net.IP{net.ParseIP("192.0.2.10")}, false)
	if err != nil {
		t.Fatalf("newAddressSource() error = %v", err)
	}
	err = targets.replace([]net.IP{net.ParseIP("192.0.2.20"), net.ParseIP("2001:db8::20")}, time.Now().Add(time.Minute), time.Now().Add(30*time.Second), nil)
	if err != nil {
		t.Fatalf("replace() error = %v", err)
	}
	state := targets.snapshot()
	if len(state.addrs) != 2 {
		t.Fatalf("addr count = %d, want 2", len(state.addrs))
	}
	if state.addrs[0] != "192.0.2.20:853" {
		t.Fatalf("first addr = %q", state.addrs[0])
	}
}

func TestScheduleRefreshRespectsThresholdAndMinimumTTL(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	cfg := config.UpstreamRefreshConfig{
		Enabled:          true,
		RefreshThreshold: config.Duration(30 * time.Second),
		MinTTL:           config.Duration(30 * time.Second),
		FailureRetry:     config.Duration(30 * time.Second),
		JitterPercent:    20,
	}
	now := time.Now()
	expiry := now.Add(10 * time.Second)
	next := scheduleRefresh(now, expiry, cfg, rng)
	if next.Before(now.Add(29 * time.Second)) {
		t.Fatalf("next refresh too early: %s", next.Sub(now))
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
	cfg.Bootstrap.Servers = []string{"resolver.test"}
	cfg.UpstreamGroups.DoH = []string{"https://resolver.test/dns-query"}

	if _, _, err := BuildManager(cfg, logging.New(logging.Level("error")), nil); err == nil {
		t.Fatal("BuildManager() succeeded, want error")
	}
}

func TestHostOverrideUpstreamBeatsBootstrapServersAtStartup(t *testing.T) {
	tlsConf, _ := testTLSConfig(t, "resolver.test")

	var bootstrapQuestions atomic.Int32
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			t.Fatalf("Unpack() error = %v", err)
		}
		if len(req.Question) != 1 {
			t.Fatalf("question count = %d, want 1", len(req.Question))
		}
		if req.Question[0].Name == "target.test." {
			bootstrapQuestions.Add(1)
		}

		resp := new(dns.Msg)
		resp.SetReply(req)
		switch req.Question[0].Qtype {
		case dns.TypeA:
			resp.Answer = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(127, 0, 0, 2)},
			}
		case dns.TypeAAAA:
			resp.Rcode = dns.RcodeNameError
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
	cfg.PrewarmPools = false
	cfg.Bootstrap.Servers = []string{"192.0.2.1"}
	cfg.UpstreamGroups.DoH = []string{"https://resolver.test:" + strconv.Itoa(port) + "/dns-query"}
	cfg.UpstreamGroups.DNS = []string{"target.test"}
	cfg.Hosts = config.HostOverrides{"resolver.test": config.IPList{net.ParseIP("127.0.0.1")}}

	mgr, _, err := BuildManager(cfg, logging.New(logging.Level("error")), nil)
	if err != nil {
		t.Fatalf("BuildManager() error = %v", err)
	}

	src := mgr.refreshCache.entries["target.test"]
	if src == nil {
		t.Fatal("target.test address source not created")
	}
	state := src.snapshot()
	if len(state.addrs) != 1 || state.addrs[0] != "127.0.0.2:53" {
		t.Fatalf("target.test bootstrap addresses = %v, want [127.0.0.2:53]", state.addrs)
	}
	if bootstrapQuestions.Load() == 0 {
		t.Fatal("startup bootstrap did not query resolver.test upstream")
	}
}

func TestDoHBootstrapPreservesHostAndSNI(t *testing.T) {
	tlsConf, serverName := testTLSConfig(t, "resolver.test")

	var hostHeader atomic.Value
	var protoMajor atomic.Int32
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		hostHeader.Store(r.Host)
		protoMajor.Store(int32(r.ProtoMajor))
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
	cfg.UpstreamGroups.DoH = []string{"https://resolver.test:" + strconv.Itoa(port) + "/dns-query"}
	cfg.Hosts = config.HostOverrides{"resolver.test": config.IPList{net.ParseIP("127.0.0.1")}}

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
	if got := protoMajor.Load(); got != 2 {
		t.Fatalf("http proto major = %d, want 2", got)
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

	targets, err := newAddressSource("resolver.test", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), "failover", []net.IP{net.ParseIP("127.0.0.1")}, false)
	if err != nil {
		t.Fatalf("newAddressSource() error = %v", err)
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
	cfg.UpstreamGroups.DoQ = []string{"quic://resolver.test:" + strconv.Itoa(addr.Port)}
	cfg.Hosts = config.HostOverrides{"resolver.test": config.IPList{net.ParseIP("127.0.0.1")}}

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

	key, err := rsa.GenerateKey(crand.Reader, 2048)
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
	der, err := x509.CreateCertificate(crand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
