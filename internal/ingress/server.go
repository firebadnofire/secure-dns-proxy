package ingress

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/resolver"
)

// Server handles UDP and TCP DNS ingress.
type Server struct {
	udp *dns.Server
	tcp *dns.Server
	res *resolver.Resolver
	log logging.Logger
}

// New constructs a DNS ingress server bound to address:port.
func New(bindAddr string, port int, res *resolver.Resolver, log logging.Logger) *Server {
	addr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	s := &Server{res: res, log: log}

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
	resp, _, err := s.res.Resolve(ctx, req)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		s.log.Warn("resolve failed", "error", err)
		return
	}
	_ = w.WriteMsg(resp)
}
