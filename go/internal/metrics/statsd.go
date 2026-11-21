// Package metrics reports the active recording session count to statsd and,
// on EC2, to CloudWatch.
package metrics

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// SessionsGauge is the statsd key for the active session count.
const SessionsGauge = "recording.sessions.count"

// Statsd is a minimal statsd gauge client. A nil *Statsd is valid and sends
// nothing.
type Statsd struct {
	prefix string
	addr   string
	tcp    bool

	mu   sync.Mutex // guards conn; only contended on TCP reconnect
	conn net.Conn
}

// NewStatsd configures the client from JAMBONES_STATSD_PREFIX, STATS_HOST
// (default 127.0.0.1), STATS_PORT (default 8125) and STATS_PROTOCOL ("tcp",
// anything else is UDP). It returns nil if the socket cannot be created.
func NewStatsd(log *slog.Logger) *Statsd {
	host := os.Getenv("STATS_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("STATS_PORT")
	if port == "" {
		port = "8125"
	}
	s := &Statsd{
		prefix: os.Getenv("JAMBONES_STATSD_PREFIX"),
		addr:   net.JoinHostPort(host, port),
		tcp:    os.Getenv("STATS_PROTOCOL") == "tcp",
	}
	if err := s.dial(); err != nil {
		log.Warn("Failed to create statsd client. Metrics will not be sent.", "addr", s.addr, "err", err)
		return nil
	}
	proto := "UDP"
	if s.tcp {
		proto = "TCP"
	}
	log.Info("Initialized statsd client", "protocol", proto, "addr", s.addr, "prefix", s.prefix)
	return s
}

func (s *Statsd) dial() error {
	network := "udp4"
	if s.tcp {
		network = "tcp4"
	}
	conn, err := net.DialTimeout(network, s.addr, 3*time.Second)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Gauge sends key:value|g. The value is formatted with six decimals, as the
// C++ service's std::to_string(double) did.
func (s *Statsd) Gauge(key string, value float64) {
	if s == nil {
		return
	}
	if s.prefix != "" {
		key = s.prefix + "." + key
	}
	msg := fmt.Sprintf("%s:%f|g", key, value)
	if s.tcp {
		msg += "\n"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil && s.dial() != nil {
		return
	}
	if _, err := s.conn.Write([]byte(msg)); err != nil && s.tcp {
		s.conn.Close()
		s.conn = nil
	}
}
