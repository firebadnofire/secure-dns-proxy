package main

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

const (
	listenAddr = "127.0.0.35:53"
	relativeUpstreamConfPath = "../etc/secure-dns-proxy/upstreams.conf"
)

var upstreams []string

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
		if strings.HasPrefix(line, "dns://") {
			address := strings.TrimPrefix(line, "dns://")
			result = append(result, address)
		} else {
			log.Printf("[WARN] Skipping unsupported line: %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("[FATAL] Error reading upstream config: %v", err)
	}
	return result
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(upstreams) == 0 {
		log.Print("[ERROR] No DNS upstreams available")
		dns.HandleFailed(w, r)
		return
	}

	c := new(dns.Client)
	resp, _, err := c.Exchange(r, upstreams[0])
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
