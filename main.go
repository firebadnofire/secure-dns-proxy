package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

const (
	listenAddr = "127.0.0.35:53"
	relativeUpstreamConfPath = "../etc/secure-dns-proxy/upstreams.conf"
)

var (
	upstreams []string
	insecure  bool
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
		log.Fatalf("[FATAL] Failed to open upstream config: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var result []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "dns://") || strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "tls://") {
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

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(upstreams) == 0 {
		log.Print("[ERROR] No DNS upstreams available")
		dns.HandleFailed(w, r)
		return
	}

	var resp *dns.Msg
	var err error

	upstream := upstreams[0] // Basic fallback for now
	if strings.HasPrefix(upstream, "dns://") {
		c := new(dns.Client)
		address := strings.TrimPrefix(upstream, "dns://")
		resp, _, err = c.Exchange(r, address)
	} else if strings.HasPrefix(upstream, "https://") {
		resp, err = forwardDNSOverHTTPS(upstream, r)
	} else if strings.HasPrefix(upstream, "tls://") {
		resp, err = forwardDNSOverTLS(upstream, r)
	} else {
		err = io.ErrUnexpectedEOF // crude placeholder
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
	flag.Parse()

	upstreams = loadUpstreams(relativeUpstreamConfPath)
	dns.HandleFunc(".", handleDNSRequest)

	udpServer := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpServer := &dns.Server{Addr: listenAddr, Net: "tcp"}

	go func() {
		log.Printf("[INFO] Starting UDP server on %s", listenAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("[FATAL] Failed to start UDP server: %v", err)
		}
	}()

	log.Printf("[INFO] Starting TCP server on %s", listenAddr)
	if err := tcpServer.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Failed to start TCP server: %v", err)
	}
}
