package ingress

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
	"archuser.org/secure-dns-proxy/internal/resolver"
)

// Server handles UDP and TCP DNS ingress.
type Server struct {
	udp     *dns.Server
	tcp     *dns.Server
	handler dns.Handler
	res     *resolver.Resolver
	log     logging.Logger
	metrics *metrics.Metrics
	addr    string
	port    int

	requestCount atomic.Uint64
	trafficIn    atomic.Uint64
	trafficOut   atomic.Uint64
}

// New constructs a DNS ingress server bound to address:port.
func New(bindAddr string, port int, res *resolver.Resolver, log logging.Logger, metrics *metrics.Metrics) *Server {
	addr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	s := &Server{res: res, log: log, metrics: metrics, addr: bindAddr, port: port}

	s.handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.handle(context.Background(), w, r)
	})

	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: s.handler, ReusePort: true, UDPSize: dns.DefaultMsgSize}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: s.handler, ReusePort: true}
	return s
}

// Start launches UDP and TCP listeners.
func (s *Server) Start() error {
	go func() {
		if err := s.udp.ListenAndServe(); err != nil {
			s.log.Error("udp server stopped", "error", err)
		}
	}()
	go func() {
		if err := s.tcp.ListenAndServe(); err != nil {
			s.log.Error("tcp server stopped", "error", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	stopCh := make(chan struct{}, 2)
	go func() { s.udp.ShutdownContext(ctx); stopCh <- struct{}{} }()
	go func() { s.tcp.ShutdownContext(ctx); stopCh <- struct{}{} }()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for i := 0; i < 2; i++ {
		select {
		case <-stopCh:
		case <-timer.C:
			return ctx.Err()
		}
	}
	return nil
}

// Rebind tears down listeners and rebinds to the configured address without
// dropping in-memory state like caches.
func (s *Server) Rebind(ctx context.Context) error {
	if err := s.Shutdown(ctx); err != nil {
		return err
	}

	addr := net.JoinHostPort(s.addr, strconv.Itoa(s.port))
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: s.handler, ReusePort: true, UDPSize: dns.DefaultMsgSize}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: s.handler, ReusePort: true}
	return s.Start()
}

func (s *Server) handle(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	resp, hit, err := s.res.Resolve(ctx, req)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		s.log.Warn("resolve failed", "error", err)
		s.logQueryAndTraffic(req, m, false)
		return
	}
	_ = w.WriteMsg(resp)
	s.logQueryAndTraffic(req, resp, hit)
}

func (s *Server) logQueryAndTraffic(req, resp *dns.Msg, cacheHit bool) {
	totalQueries := s.requestCount.Add(1)
	if s.metrics != nil {
		s.metrics.RecordRequest()
	}

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

func bytesToMiB(v uint64) float64 { return float64(v) / (1024 * 1024) }

func bytesToGiB(v uint64) float64 { return float64(v) / (1024 * 1024 * 1024) }
