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
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	relativeUpstreamConfPath = "../etc/secure-dns-proxy/upstreams.conf"
	systemFallbackUpstreamConfPath = "/etc/secure-dns-proxy/upstreams.conf"
)

var (
	upstreams    []string
	insecure     bool
	enablePMTUD  bool
	port         int
	bind         string
)

func getExecutableDir() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[FATAL] Cannot determine executable path: %v", err)
	}
	return filepath.Dir(exePath)
}

func loadUpstreams(relPath string) []string {
	absPath := filepath.Join(getExecutableDir(), relPath)
	file, err := os.Open(absPath)
	if err != nil {
		log.Printf("[WARN] Failed to open local upstream config at %s: %v", absPath, err)
		log.Printf("[INFO] Falling back to system config at %s", systemFallbackUpstreamConfPath)
		file, err = os.Open(systemFallbackUpstreamConfPath)
		if err != nil {
			log.Fatalf("[FATAL] Failed to open fallback upstream config: %v", err)
		}
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

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(upstreams) == 0 {
		log.Print("[ERROR] No DNS upstreams available")
		dns.HandleFailed(w, r)
		return
	}

	var resp *dns.Msg
	var err error

	upstream := upstreams[0]
	switch {
	case strings.HasPrefix(upstream, "dns://"):
		c := new(dns.Client)
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
		err = io.ErrUnexpectedEOF
	}

	if err != nil {
		log.Printf("[ERROR] DNS forward failed: %v", err)
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
