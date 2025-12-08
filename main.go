package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	relativeUpstreamConfPath       = "../etc/secure-dns-proxy/upstreams.conf"
	homeFallbackUpstreamConfPath   = "~/.config/secure-dns-proxy/upstreams.conf"
	systemFallbackUpstreamConfPath = "/etc/secure-dns-proxy/upstreams.conf"
)

var (
	upstreams       []string
	insecure        bool
	enablePMTUD     bool
	port            int
	bind            string
	upstreamTimeout time.Duration
)

const (
	maxTLSPoolSize   = 4
	maxQUICPoolSize  = 4
	defaultTLSNext   = "tls"
	defaultQUICProto = "doq"
)

type tlsPool struct {
	mu    sync.Mutex
	conns map[string][]*tls.Conn
}

func newTLSPool() *tlsPool {
	return &tlsPool{conns: make(map[string][]*tls.Conn)}
}

func (p *tlsPool) get(host string) *tls.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.conns[host]
	if len(conns) == 0 {
		return nil
	}
	conn := conns[len(conns)-1]
	p.conns[host] = conns[:len(conns)-1]
	return conn
}

func (p *tlsPool) put(host string, conn *tls.Conn) {
	if conn == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.conns[host]
	if len(conns) >= maxTLSPoolSize {
		conn.Close()
		return
	}
	p.conns[host] = append(conns, conn)
}

type quicPool struct {
	mu       sync.Mutex
	sessions map[string][]quic.Connection
}

func newQUICPool() *quicPool {
	return &quicPool{sessions: make(map[string][]quic.Connection)}
}

func (p *quicPool) get(host string) quic.Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	sessions := p.sessions[host]
	if len(sessions) == 0 {
		return nil
	}
	s := sessions[len(sessions)-1]
	p.sessions[host] = sessions[:len(sessions)-1]
	return s
}

func (p *quicPool) put(host string, session quic.Connection) {
	if session == nil {
		return
	}
	if session.Context().Err() != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sessions := p.sessions[host]
	if len(sessions) >= maxQUICPoolSize {
		session.CloseWithError(0, "closing idle session: pool full")
		return
	}
	p.sessions[host] = append(sessions, session)
}

var (
	tlsConnPool  = newTLSPool()
	quicSessPool = newQUICPool()
)

func getExecutableDir() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[FATAL] Cannot determine executable path: %v", err)
	}
	return filepath.Dir(exePath)
}

func expandUser(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("[FATAL] Cannot determine home directory: %v", err)
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

func loadUpstreams(relPath string) []string {
	paths := []string{
		filepath.Join(getExecutableDir(), relPath),
		expandUser(homeFallbackUpstreamConfPath),
		systemFallbackUpstreamConfPath,
	}

	var file *os.File
	var err error
	for _, absPath := range paths {
		file, err = os.Open(absPath)
		if err == nil {
			log.Printf("[INFO] Loaded upstream config from %s", absPath)
			break
		}
		log.Printf("[WARN] Failed to open upstream config at %s: %v", absPath, err)
	}
	if file == nil {
		log.Fatalf("[FATAL] All attempts to load upstream config failed")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var result []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "dns://") || strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "tls://") || strings.HasPrefix(line, "quic://") {
			result = append(result, line)
		} else {
			log.Printf("[WARN] Skipping unsupported line: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("[FATAL] Error reading upstream config: %v", err)
	}
	return result
}

func watchContext(ctx context.Context, onCancel func()) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			onCancel()
		case <-done:
		}
	}()
	return func() { close(done) }
}

func forwardDNSOverHTTPS(ctx context.Context, upstream string, msg *dns.Msg) (*dns.Msg, error) {
	raw, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", upstream, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: upstreamTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBody); err != nil {
		return nil, err
	}
	return response, nil
}

func forwardDNSOverTLS(ctx context.Context, upstream string, msg *dns.Msg) (*dns.Msg, error) {
	host := strings.TrimPrefix(upstream, "tls://")
	if !strings.Contains(host, ":") {
		host += ":853"
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(host, ":")[0],
		InsecureSkipVerify: insecure,
		NextProtos:         []string{defaultTLSNext},
	}

	conn := tlsConnPool.get(host)
	if conn == nil {
		dialer := &tls.Dialer{
			Config: tlsConfig,
			NetDialer: &net.Dialer{
				Timeout:   upstreamTimeout,
				KeepAlive: 30 * time.Second,
			},
		}
		var err error
		netConn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		var ok bool
		conn, ok = netConn.(*tls.Conn)
		if !ok {
			netConn.Close()
			return nil, fmt.Errorf("unexpected TLS connection type %T", netConn)
		}
	}

	stopWatcher := watchContext(ctx, func() { conn.Close() })
	defer stopWatcher()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(msg); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		conn.Close()
		return nil, err
	}

	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	conn.SetDeadline(time.Time{})
	tlsConnPool.put(host, conn)
	return resp, nil
}

func forwardDNSOverQUIC(ctx context.Context, upstream string, msg *dns.Msg) (*dns.Msg, error) {
	hostPort := strings.TrimPrefix(upstream, "quic://")
	if !strings.Contains(hostPort, ":") {
		hostPort += ":853"
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(hostPort, ":")[0],
		InsecureSkipVerify: insecure,
		NextProtos:         []string{defaultQUICProto},
	}
	quicConf := &quic.Config{DisablePathMTUDiscovery: !enablePMTUD, KeepAlivePeriod: 30 * time.Second}

	session := quicSessPool.get(hostPort)
	if session == nil {
		var err error
		session, err = quic.DialAddr(ctx, hostPort, tlsConfig, quicConf)
		if err != nil {
			return nil, err
		}
	}

	stopWatcher := watchContext(ctx, func() { session.CloseWithError(0, "context cancelled") })
	defer stopWatcher()

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		if ctx.Err() != nil {
			session.CloseWithError(0, "context cancelled")
		}
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
	}

	raw, err := msg.Pack()
	if err != nil {
		stream.Close()
		return nil, err
	}

	length := uint16(len(raw))
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, length)
	if _, err := stream.Write(lenBuf); err != nil {
		stream.Close()
		return nil, err
	}
	if _, err := stream.Write(raw); err != nil {
		stream.Close()
		return nil, err
	}
	stream.Close()

	respBytes, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}
	if len(respBytes) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	body := respBytes[2:]

	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		session.CloseWithError(0, "invalid response")
		return nil, err
	}

	if ctx.Err() != nil || session.Context().Err() != nil {
		session.CloseWithError(0, "context expired")
		return nil, ctx.Err()
	}
	stream.SetDeadline(time.Time{})
	quicSessPool.put(hostPort, session)
	return response, nil
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(upstreams) == 0 {
		log.Print("[ERROR] No DNS upstreams available")
		dns.HandleFailed(w, r)
		return
	}

	var resp *dns.Msg
	var err error
	for _, upstream := range upstreams {
		ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		switch {
		case strings.HasPrefix(upstream, "dns://"):
			c := new(dns.Client)
			address := strings.TrimPrefix(upstream, "dns://")
			if !strings.Contains(address, ":") {
				address += ":53"
			}
			resp, _, err = c.ExchangeContext(ctx, r, address)
		case strings.HasPrefix(upstream, "https://"):
			resp, err = forwardDNSOverHTTPS(ctx, upstream, r)
		case strings.HasPrefix(upstream, "tls://"):
			resp, err = forwardDNSOverTLS(ctx, upstream, r)
		case strings.HasPrefix(upstream, "quic://"):
			resp, err = forwardDNSOverQUIC(ctx, upstream, r)
		default:
			err = io.ErrUnexpectedEOF
		}
		cancel()

		if err != nil || resp == nil || len(resp.Answer) == 0 {
			log.Printf("[WARN] Upstream %s failed: %v", upstream, err)
			continue
		} else {
			log.Printf("[INFO] Successfully resolved via upstream: %s", upstream)
			break
		}
	}

	if resp == nil || len(resp.Answer) == 0 {
		log.Printf("[ERROR] All upstreams failed or returned no answer")
		dns.HandleFailed(w, r)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[ERROR] Failed to write DNS response: %v", err)
	}
}

func main() {
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
	flag.BoolVar(&enablePMTUD, "pmtud", true, "Enable QUIC Path MTU Discovery")
	flag.IntVar(&port, "port", 53, "Port to bind on localhost")
	flag.StringVar(&bind, "bind", "127.0.0.35", "Address to bind DNS server to")
	flag.DurationVar(&upstreamTimeout, "upstream-timeout", 5*time.Second, "Timeout for upstream requests")
	flag.Parse()

	if upstreamTimeout <= 0 {
		upstreamTimeout = 5 * time.Second
	}

	addr := bind + ":" + strconv.Itoa(port)

	upstreams = loadUpstreams(relativeUpstreamConfPath)
	dns.HandleFunc(".", handleDNSRequest)

	udpServer := &dns.Server{Addr: addr, Net: "udp"}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp"}

	go func() {
		log.Printf("[INFO] Starting UDP server on %s", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("[FATAL] Failed to start UDP server: %v", err)
		}
	}()

	log.Printf("[INFO] Starting TCP server on %s", addr)
	if err := tcpServer.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Failed to start TCP server: %v", err)
	}
}
