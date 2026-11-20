package router

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"doh-autoproxy/internal/config"
	"github.com/miekg/dns"
)

// Benchmark the full GeoIP fallback (3 CN + 2 overseas), without any network I/O.
// Measure first reply separately from round completion; include warming in calls/query.
type timedUpstream struct {
	calls *atomic.Int64
	delay time.Duration
	kind  string
	index int
}

func (u timedUpstream) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	u.calls.Add(1)
	timer := time.NewTimer(u.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	m := new(dns.Msg).SetReply(q)
	switch {
	case u.kind == "nxdomain":
		m.Rcode = dns.RcodeNameError
	case u.kind == "empty-first" && u.index == 0:
	default:
		m.Answer = newAResp(q.Question[0].Name, "192.0.2.1", 120).Answer
	}
	return m, nil
}

func BenchmarkParallelCold(b *testing.B) {
	for _, kind := range []string{"positive", "nxdomain", "empty-first"} {
		b.Run(kind, func(b *testing.B) {
			var calls atomic.Int64
			r := NewRouterWithMode(&config.Config{}, nil, nil, true)
			for i, d := range []time.Duration{2, 5, 8} {
				r.cnClients = append(r.cnClients, timedUpstream{&calls, d * time.Millisecond, kind, i})
			}
			for i, d := range []time.Duration{2, 6} {
				r.overseasClients = append(r.overseasClients, timedUpstream{&calls, d * time.Millisecond, kind, i})
			}
			latency := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for i := range b.N {
				q := new(dns.Msg).SetQuestion(fmt.Sprintf("q%d.example.", i), dns.TypeA)
				t := time.Now()
				m, err := r.Route(context.Background(), q, "")
				latency = append(latency, time.Since(t))
				if err != nil || m == nil {
					b.Fatalf("missing response: %v", err)
				}
				if kind == "nxdomain" && m.Rcode != dns.RcodeNameError {
					b.Fatalf("lost negative response: %v", m)
				}
				for {
					r.aggregateCacheMu.RLock()
					active := len(r.aggregateWarmup)
					r.aggregateCacheMu.RUnlock()
					if active == 0 {
						break
					}
					if time.Since(t) > 2*time.Second {
						b.Fatal("warmup did not finish")
					}
					time.Sleep(100 * time.Microsecond)
				}
			}
			b.StopTimer()
			slices.Sort(latency)
			b.ReportMetric(float64(calls.Load())/float64(b.N), "calls/query")
			for _, p := range []int{50, 95} {
				b.ReportMetric(float64(latency[(len(latency)*p+99)/100-1])/float64(time.Millisecond), fmt.Sprintf("first-p%d-ms", p))
			}
		})
	}
}

// Each burst is a new domain, with 16 independent downstream requests hitting
// the same two groups. All timings are in-process; no network is contacted.
func BenchmarkParallelBurst(b *testing.B) {
	const burst = 16
	for _, kind := range []string{"positive", "nxdomain"} {
		b.Run(kind, func(b *testing.B) {
			var calls atomic.Int64
			r := NewRouterWithMode(&config.Config{}, nil, nil, true)
			for i, d := range []time.Duration{4, 6, 8} {
				r.cnClients = append(r.cnClients, timedUpstream{&calls, d * time.Millisecond, kind, i})
			}
			for i, d := range []time.Duration{4, 6} {
				r.overseasClients = append(r.overseasClients, timedUpstream{&calls, d * time.Millisecond, kind, i})
			}
			latencies := make([]time.Duration, 0, b.N*burst)
			for i := range b.N {
				name := fmt.Sprintf("burst%d.example.", i)
				start := make(chan struct{})
				done := make(chan time.Duration, burst)
				for id := range burst {
					go func() {
						q := new(dns.Msg).SetQuestion(name, dns.TypeA)
						q.Id = uint16(id)
						<-start
						t := time.Now()
						m, err := r.Route(context.Background(), q, "")
						elapsed := time.Since(t)
						if err != nil || m == nil || m.Id != q.Id || (kind == "nxdomain") != (m.Rcode == dns.RcodeNameError) {
							b.Errorf("wrong response to %d: %v, %v", id, m, err)
						}
						done <- elapsed
					}()
				}
				close(start)
				for range burst {
					latencies = append(latencies, <-done)
				}
				deadline := time.Now().Add(2 * time.Second)
				for {
					r.aggregateCacheMu.RLock()
					busy := len(r.aggregateWarmup) > 0
					r.aggregateCacheMu.RUnlock()
					if !busy {
						break
					}
					if time.Now().After(deadline) {
						b.Fatal("round did not finish")
					}
					time.Sleep(100 * time.Microsecond)
				}
			}
			b.StopTimer()
			slices.Sort(latencies)
			b.ReportMetric(float64(calls.Load())/float64(b.N), "calls/burst")
			for _, p := range []int{50, 95} {
				b.ReportMetric(float64(latencies[(len(latencies)*p+99)/100-1])/float64(time.Millisecond), fmt.Sprintf("first-p%d-ms", p))
			}
		})
	}
}
