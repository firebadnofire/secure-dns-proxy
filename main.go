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
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	upstreams   []string
	insecure    bool
	enablePMTUD bool
	port        int
	bind        string
	httpClient  *http.Client
)

// getExecutableDir returns the directory containing the current executable.
func getExecutableDir() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[FATAL] Cannot determine executable path: %v", err)
	}
	return filepath.Dir(exePath)
}

// expandUser expands the ~ prefix in a path to the user's home directory.
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

// loadUpstreams loads upstream DNS server configurations from a config file.
// It tries multiple paths in order until a valid config file is found.
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

// forwardDNSOverHTTPS forwards a DNS query over HTTPS (DoH).
func forwardDNSOverHTTPS(upstream string, msg *dns.Msg) (*dns.Msg, error) {
	raw, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", upstream, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBody); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}
	return response, nil
}

// forwardDNSOverTLS forwards a DNS query over TLS (DoT).
func forwardDNSOverTLS(upstream string, msg *dns.Msg) (*dns.Msg, error) {
	host := strings.TrimPrefix(upstream, "tls://")
	if !strings.Contains(host, ":") {
		host += ":853"
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(host, ":")[0],
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"dot"},
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("failed to write DNS message: %w", err)
	}
	response, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %w", err)
	}
	return response, nil
}

// forwardDNSOverQUIC forwards a DNS query over QUIC (DoQ).
func forwardDNSOverQUIC(upstream string, msg *dns.Msg) (*dns.Msg, error) {
	hostPort := strings.TrimPrefix(upstream, "quic://")
	if !strings.Contains(hostPort, ":") {
		hostPort += ":853"
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(hostPort, ":")[0],
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"doq"},
		MinVersion:         tls.VersionTLS12,
	}
	quicConf := &quic.Config{DisablePathMTUDiscovery: !enablePMTUD}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := quic.DialAddr(ctx, hostPort, tlsConfig, quicConf)
	if err != nil {
		return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open QUIC stream: %w", err)
	}
	defer stream.Close()

	raw, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Write DNS message with length prefix
	length := uint16(len(raw))
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, length)
	if _, err := stream.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("failed to write message length: %w", err)
	}
	if _, err := stream.Write(raw); err != nil {
		return nil, fmt.Errorf("failed to write DNS message: %w", err)
	}

	// Signal end of writing
	stream.Close()

	respBytes, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if len(respBytes) < 2 {
		return nil, fmt.Errorf("response too short: got %d bytes, expected at least 2", len(respBytes))
	}
	body := respBytes[2:]

	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}
	return response, nil
}

// handleDNSRequest processes incoming DNS requests and forwards them to configured upstreams.
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(upstreams) == 0 {
		log.Print("[ERROR] No DNS upstreams available")
		dns.HandleFailed(w, r)
		return
	}

	var resp *dns.Msg
	var err error
	for _, upstream := range upstreams {
		switch {
		case strings.HasPrefix(upstream, "dns://"):
			c := new(dns.Client)
			c.Timeout = 10 * time.Second
			address := strings.TrimPrefix(upstream, "dns://")
			if !strings.Contains(address, ":") {
				address += ":53"
			}
			resp, _, err = c.Exchange(r, address)
		case strings.HasPrefix(upstream, "https://"):
			resp, err = forwardDNSOverHTTPS(upstream, r)
		case strings.HasPrefix(upstream, "tls://"):
			resp, err = forwardDNSOverTLS(upstream, r)
		case strings.HasPrefix(upstream, "quic://"):
			resp, err = forwardDNSOverQUIC(upstream, r)
		default:
			log.Printf("[WARN] Unsupported upstream protocol: %s", upstream)
			continue
		}

		if err != nil {
			log.Printf("[WARN] Upstream %s failed: %v", upstream, err)
			continue
		}

		// A valid response was received (even if it has no answers or is NXDOMAIN)
		if resp != nil {
			log.Printf("[INFO] Successfully resolved via upstream: %s", upstream)
			break
		}
	}

	if resp == nil {
		log.Printf("[ERROR] All upstreams failed to return a response")
		dns.HandleFailed(w, r)
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[ERROR] Failed to write DNS response: %v", err)
	}
}

func main() {
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification (DANGEROUS - use only for testing)")
	flag.BoolVar(&enablePMTUD, "pmtud", true, "Enable QUIC Path MTU Discovery")
	flag.IntVar(&port, "port", 53, "Port to bind on localhost")
	flag.StringVar(&bind, "bind", "127.0.0.35", "Address to bind DNS server to")
	flag.Parse()

	// Validate port range
	if port < 1 || port > 65535 {
		log.Fatalf("[FATAL] Invalid port number: %d (must be between 1 and 65535)", port)
	}

	// Validate bind address
	if net.ParseIP(bind) == nil {
		log.Fatalf("[FATAL] Invalid bind address: %s", bind)
	}

	// Warn about insecure mode
	if insecure {
		log.Printf("[WARNING] ⚠️  Running in INSECURE mode - TLS certificate verification is DISABLED!")
		log.Printf("[WARNING] ⚠️  This should ONLY be used for testing purposes!")
	}

	addr := bind + ":" + strconv.Itoa(port)

	// Initialize HTTP client with connection pooling and timeouts
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	upstreams = loadUpstreams(relativeUpstreamConfPath)
	if len(upstreams) == 0 {
		log.Fatalf("[FATAL] No valid upstreams found in configuration")
	}
	log.Printf("[INFO] Loaded %d upstream(s)", len(upstreams))

	dns.HandleFunc(".", handleDNSRequest)

	udpServer := &dns.Server{Addr: addr, Net: "udp"}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp"}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[INFO] Shutdown signal received, stopping servers...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := udpServer.ShutdownContext(ctx); err != nil {
			log.Printf("[ERROR] Error shutting down UDP server: %v", err)
		}
		if err := tcpServer.ShutdownContext(ctx); err != nil {
			log.Printf("[ERROR] Error shutting down TCP server: %v", err)
		}
	}()

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
