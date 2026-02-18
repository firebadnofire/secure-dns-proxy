// Package ingress exposes the UDP/TCP DNS server used for client queries.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
	"archuser.org/secure-dns-proxy/internal/resolver"
)

// Server handles UDP and TCP DNS ingress.
type Server struct {
	// udp/tcp servers share the same handler to process DNS queries.
	udp *dns.Server
	tcp *dns.Server
	// res forwards questions to the resolver (cache + upstreams).
	res *resolver.Resolver
	// log emits structured diagnostics.
	log logging.Logger
	// metrics tracks counters when enabled.
	metrics *metrics.Metrics

	// requestCount/traffic counters are local aggregates for logging.
	requestCount atomic.Uint64
	trafficIn    atomic.Uint64
	trafficOut   atomic.Uint64
}

// New constructs a DNS ingress server bound to address:port.
func New(bindAddr string, port int, res *resolver.Resolver, log logging.Logger, metrics *metrics.Metrics) *Server {
	addr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	s := &Server{res: res, log: log, metrics: metrics}

	// Handler delegates request processing to the resolver.
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.handle(context.Background(), w, r)
	})

	// UDP and TCP servers share the same address and handler.
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: handler, ReusePort: true, UDPSize: dns.DefaultMsgSize}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: handler, ReusePort: true}
	return s
}

// Start launches UDP and TCP listeners.
func (s *Server) Start() error {
	udpConn, err := net.ListenPacket("udp", s.udp.Addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", s.udp.Addr, err)
	}
	tcpListener, err := net.Listen("tcp", s.tcp.Addr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("listen tcp %s: %w", s.tcp.Addr, err)
	}

	s.udp.PacketConn = udpConn
	s.tcp.Listener = tcpListener

	go func() {
		if err := s.udp.ActivateAndServe(); err != nil {
			s.log.Error("udp server stopped", "error", err)
		}
	}()
	go func() {
		if err := s.tcp.ActivateAndServe(); err != nil {
			s.log.Error("tcp server stopped", "error", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	// Shutdown both servers concurrently and wait for both to return.
	stopCh := make(chan error, 2)
	go func() { stopCh <- s.udp.ShutdownContext(ctx) }()
	go func() { stopCh <- s.tcp.ShutdownContext(ctx) }()

	var shutdownErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-stopCh:
			if err != nil {
				shutdownErr = errors.Join(shutdownErr, err)
			}
		case <-ctx.Done():
			return errors.Join(shutdownErr, ctx.Err())
		}
	}
	return shutdownErr
}

// handle executes a single DNS request/response exchange.
func (s *Server) handle(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	resp, hit, err := s.res.Resolve(ctx, req)
	if err != nil {
		// Preserve the original question with a SERVFAIL response.
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		s.log.Warn("resolve failed", "error", err)
		s.logQueryAndTraffic(req, m, false)
		return
	}
	// Write the successful response back to the client.
	_ = w.WriteMsg(resp)
	s.logQueryAndTraffic(req, resp, hit)
}

// logQueryAndTraffic emits per-query log lines and updates traffic counters.
func (s *Server) logQueryAndTraffic(req, resp *dns.Msg, cacheHit bool) {
	totalQueries := s.requestCount.Add(1)
	if s.metrics != nil {
		// Mirror totals into the metrics sink if enabled.
		s.metrics.RecordRequest()
	}

	// Pull out response metadata for structured logging.
	answers := 0
	authorities := 0
	extra := 0
	rcode := "UNKNOWN"
	if resp != nil {
		answers = len(resp.Answer)
		authorities = len(resp.Ns)
		extra = len(resp.Extra)
		rcode = dns.RcodeToString[resp.Rcode]
	}

	if len(req.Question) > 0 {
		q := req.Question[0]
		args := []any{"name", q.Name, "type", dns.TypeToString[q.Qtype], "class", dns.ClassToString[q.Qclass], "rcode", rcode, "cache_hit", cacheHit, "answer_records", answers, "authority_records", authorities, "extra_records", extra, "queries_total", totalQueries}
		s.log.Info("query", args...)
	}

	// Track ingress/egress bytes and log cumulative totals.
	reqSize := uint64(req.Len())
	respSize := uint64(0)
	if resp != nil {
		respSize = uint64(resp.Len())
	}
	inTotal := s.trafficIn.Add(reqSize)
	outTotal := s.trafficOut.Add(respSize)
	if s.metrics != nil {
		s.metrics.AddTraffic(reqSize, respSize)
	}

	s.log.Info("cumulative traffic", "in_bytes", inTotal, "in_mib", fmt.Sprintf("%.3f", bytesToMiB(inTotal)), "in_gib", fmt.Sprintf("%.3f", bytesToGiB(inTotal)), "out_bytes", outTotal, "out_mib", fmt.Sprintf("%.3f", bytesToMiB(outTotal)), "out_gib", fmt.Sprintf("%.3f", bytesToGiB(outTotal)))
}

// bytesToMiB converts bytes to mebibytes.
func bytesToMiB(v uint64) float64 { return float64(v) / (1024 * 1024) }

// bytesToGiB converts bytes to gibibytes.
func bytesToGiB(v uint64) float64 { return float64(v) / (1024 * 1024 * 1024) }
