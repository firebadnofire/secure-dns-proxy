package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	consecutiveFailureThreshold    = 3
	initialBackoff                 = time.Second
	maxBackoff                     = 30 * time.Second
)

var (
	upstreams   []*Upstream
	insecure    bool
	enablePMTUD bool
	port        int
	bind        string
	rotate      bool

	upstreamMu sync.Mutex
)

type Upstream struct {
	URL                 string
	successCount        int
	failureCount        int
	consecutiveFailures int
	lastErrorTime       time.Time
	penaltyUntil        time.Time
	backoff             time.Duration
	lastLatency         time.Duration
}

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

func loadUpstreams(relPath string) []*Upstream {
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
	var result []*Upstream
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "dns://") || strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "tls://") || strings.HasPrefix(line, "quic://") {
			result = append(result, &Upstream{URL: line, backoff: initialBackoff})
		} else {
			log.Printf("[WARN] Skipping unsupported line: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("[FATAL] Error reading upstream config: %v", err)
	}
	return result
}

func forwardDNSOverHTTPS(upstream string, msg *dns.Msg) (*dns.Msg, error) {
	raw, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", upstream, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{}
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

func forwardDNSOverTLS(upstream string, msg *dns.Msg) (*dns.Msg, error) {
	host := strings.TrimPrefix(upstream, "tls://")
	if !strings.Contains(host, ":") {
		host += ":853"
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(host, ":")[0],
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"tls"},
	}
	conn, err := tls.Dial("tcp", host, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

func forwardDNSOverQUIC(upstream string, msg *dns.Msg) (*dns.Msg, error) {
	hostPort := strings.TrimPrefix(upstream, "quic://")
	if !strings.Contains(hostPort, ":") {
		hostPort += ":853"
	}

	tlsConfig := &tls.Config{
		ServerName:         strings.Split(hostPort, ":")[0],
		InsecureSkipVerify: insecure,
		NextProtos:         []string{"doq"},
	}
	quicConf := &quic.Config{DisablePathMTUDiscovery: !enablePMTUD}

	session, err := quic.DialAddr(context.Background(), hostPort, tlsConfig, quicConf)
	if err != nil {
		return nil, err
	}
	defer session.CloseWithError(0, "")

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return response, nil
}

func getSortedUpstreams() []*Upstream {
	upstreamMu.Lock()
	defer upstreamMu.Unlock()

	ordered := make([]*Upstream, len(upstreams))
	copy(ordered, upstreams)

	if rotate {
		now := time.Now()
		sort.SliceStable(ordered, func(i, j int) bool {
			iScore := upstreamScore(ordered[i], now)
			jScore := upstreamScore(ordered[j], now)
			return iScore < jScore
		})
	}

	return ordered
}

func upstreamScore(u *Upstream, now time.Time) float64 {
	latency := u.lastLatency
	if latency == 0 {
		latency = 500 * time.Millisecond
	}
	health := float64(u.successCount+1) / float64(u.failureCount+1)
	penalty := 1.0
	if now.Before(u.penaltyUntil) {
		penalty = 10.0
	}
	return float64(latency) * penalty / health
}

func markUpstreamFailure(u *Upstream, err error) {
	u.failureCount++
	u.consecutiveFailures++
	u.lastErrorTime = time.Now()

	if u.consecutiveFailures >= consecutiveFailureThreshold {
		u.penaltyUntil = time.Now().Add(u.backoff)
		if u.backoff < maxBackoff {
			nextBackoff := u.backoff * 2
			if nextBackoff > maxBackoff {
				nextBackoff = maxBackoff
			}
			u.backoff = nextBackoff
		}
		log.Printf("[WARN] Penalizing upstream %s for %s due to consecutive failures: %v", u.URL, u.penaltyUntil.Sub(time.Now()), err)
	}
}

func markUpstreamSuccess(u *Upstream) {
	u.successCount++
	u.consecutiveFailures = 0
	u.penaltyUntil = time.Time{}
	u.backoff = initialBackoff
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(upstreams) == 0 {
		log.Print("[ERROR] No DNS upstreams available")
		dns.HandleFailed(w, r)
		return
	}

	var resp *dns.Msg
	var err error
	for _, upstream := range getSortedUpstreams() {
		upstreamMu.Lock()
		if time.Now().Before(upstream.penaltyUntil) {
			log.Printf("[INFO] Skipping penalized upstream %s until %s", upstream.URL, upstream.penaltyUntil.Format(time.RFC3339))
			upstreamMu.Unlock()
			continue
		}
		upstreamMu.Unlock()

		start := time.Now()
		switch {
		case strings.HasPrefix(upstream.URL, "dns://"):
			c := new(dns.Client)
			address := strings.TrimPrefix(upstream.URL, "dns://")
			if !strings.Contains(address, ":") {
				address += ":53"
			}
			resp, _, err = c.Exchange(r, address)
		case strings.HasPrefix(upstream.URL, "https://"):
			resp, err = forwardDNSOverHTTPS(upstream.URL, r)
		case strings.HasPrefix(upstream.URL, "tls://"):
			resp, err = forwardDNSOverTLS(upstream.URL, r)
		case strings.HasPrefix(upstream.URL, "quic://"):
			resp, err = forwardDNSOverQUIC(upstream.URL, r)
		default:
			err = io.ErrUnexpectedEOF
		}
		latency := time.Since(start)

		upstreamMu.Lock()
		upstream.lastLatency = latency
		if err != nil || resp == nil || len(resp.Answer) == 0 {
			markUpstreamFailure(upstream, err)
			upstreamMu.Unlock()
			log.Printf("[WARN] Upstream %s failed: %v", upstream.URL, err)
			continue
		}
		markUpstreamSuccess(upstream)
		upstreamMu.Unlock()
		log.Printf("[INFO] Successfully resolved via upstream: %s (latency: %s)", upstream.URL, latency)
		break
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
	flag.BoolVar(&rotate, "rotate-upstreams", false, "Rotate upstream order based on recent health")
	flag.Parse()

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
