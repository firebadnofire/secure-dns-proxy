package ingress

import (
	"context"
	"fmt"
	"net"
	"strconv"
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
	res     *resolver.Resolver
	log     logging.Logger
	metrics *metrics.Metrics
}

// New constructs a DNS ingress server bound to address:port.
func New(bindAddr string, port int, res *resolver.Resolver, log logging.Logger, metrics *metrics.Metrics) *Server {
	addr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	s := &Server{res: res, log: log, metrics: metrics}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.handle(context.Background(), w, r)
	})

	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: handler, ReusePort: true, UDPSize: dns.DefaultMsgSize}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: handler, ReusePort: true}
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
	if len(req.Question) > 0 {
		q := req.Question[0]
		s.log.Info("query", "name", q.Name, "type", dns.TypeToString[q.Qtype], "class", dns.ClassToString[q.Qclass], "rcode", dns.RcodeToString[resp.Rcode], "cache_hit", cacheHit)
	}

	if s.metrics == nil {
		return
	}

	reqSize := uint64(req.Len())
	respSize := uint64(resp.Len())
	inTotal, outTotal := s.metrics.AddTraffic(reqSize, respSize)

	s.log.Info("cumulative traffic", "in_bytes", inTotal, "in_mib", fmt.Sprintf("%.3f", bytesToMiB(inTotal)), "in_gib", fmt.Sprintf("%.3f", bytesToGiB(inTotal)), "out_bytes", outTotal, "out_mib", fmt.Sprintf("%.3f", bytesToMiB(outTotal)), "out_gib", fmt.Sprintf("%.3f", bytesToGiB(outTotal)))
}

func bytesToMiB(v uint64) float64 { return float64(v) / (1024 * 1024) }

func bytesToGiB(v uint64) float64 { return float64(v) / (1024 * 1024 * 1024) }
