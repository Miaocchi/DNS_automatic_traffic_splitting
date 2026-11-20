package router

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	clientpkg "doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"
	"github.com/miekg/dns"
)

func negativeResponse(name string, rcode int, ttl, minimum uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Rcode = rcode
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: minimum}}
	return m
}

func waitForFlightDone(t *testing.T, r *Router, key string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.aggregateCacheMu.RLock()
		_, active := r.aggregateWarmup[key]
		r.aggregateCacheMu.RUnlock()
		if !active {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("flight %q did not finish", key)
}

func TestParallelCachesSOABackedNegativeResponses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode int
	}{
		{name: "nxdomain", rcode: dns.RcodeNameError},
		{name: "nodata", rcode: dns.RcodeSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := upstreamFunc(func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
				calls.Add(1)
				return negativeResponse(req.Question[0].Name, tc.rcode, 60, 30), nil
			})
			r := NewRouterWithMode(&config.Config{}, nil, nil, true)
			firstReq := new(dns.Msg).SetQuestion("missing.example.", dns.TypeA)
			firstReq.Id = 0x1111
			first, err := r.resolveByMode(context.Background(), firstReq, []clientpkg.DNSClient{upstream}, "cn")
			if err != nil || first == nil || first.Rcode != tc.rcode {
				t.Fatalf("first response: %#v, %v", first, err)
			}
			key := buildAggregateCacheKey(firstReq, "cn")
			waitForFlightDone(t, r, key)

			secondReq := firstReq.Copy()
			secondReq.Id = 0x2222
			second, err := r.resolveByMode(context.Background(), secondReq, []clientpkg.DNSClient{upstream}, "cn")
			if err != nil || second == nil || second.Rcode != tc.rcode {
				t.Fatalf("cached response: %#v, %v", second, err)
			}
			if second.Id != secondReq.Id || len(second.Ns) != 1 || second.Ns[0].Header().Ttl == 0 || second.Ns[0].Header().Ttl > 30 {
				t.Fatalf("cached response identity/TTL incorrect: %#v", second)
			}
			if calls.Load() != 1 {
				t.Fatalf("expected one upstream call, got %d", calls.Load())
			}
		})
	}
}

func TestParallelDoesNotCacheUnverifiableNegativeResponses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode int
	}{
		{name: "no-soa", rcode: dns.RcodeNameError},
		{name: "servfail", rcode: dns.RcodeServerFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := upstreamFunc(func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
				calls.Add(1)
				m := new(dns.Msg)
				m.SetQuestion(req.Question[0].Name, dns.TypeA)
				m.Rcode = tc.rcode
				return m, nil
			})
			r := NewRouterWithMode(&config.Config{}, nil, nil, true)
			req := new(dns.Msg).SetQuestion("missing.example.", dns.TypeA)
			if _, err := r.resolveByMode(context.Background(), req, []clientpkg.DNSClient{upstream}, "cn"); err != nil {
				t.Fatalf("first query: %v", err)
			}
			waitForFlightDone(t, r, buildAggregateCacheKey(req, "cn"))
			if _, err := r.resolveByMode(context.Background(), req, []clientpkg.DNSClient{upstream}, "cn"); err != nil {
				t.Fatalf("second query: %v", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("expected no negative cache entry, got %d upstream calls", calls.Load())
			}
		})
	}
}
