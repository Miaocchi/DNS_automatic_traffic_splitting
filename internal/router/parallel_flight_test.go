package router

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"
	"github.com/miekg/dns"
)

func TestParallelJoinSurvivesLeaderCancellation(t *testing.T) {
	r := NewRouterWithMode(&config.Config{}, nil, nil, true)
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	clients := []client.DNSClient{upstreamFunc(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		calls.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m := new(dns.Msg).SetReply(q)
		m.Answer = newAResp(q.Question[0].Name, "192.0.2.1", 120).Answer
		return m, nil
	})}
	leader := new(dns.Msg).SetQuestion("EXAMPLE.test.", dns.TypeA)
	key := buildAggregateCacheKey(leader, "cn")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	owner, leave := context.WithCancel(ctx)
	defer leave()
	canceled := make(chan error, 1)
	go func() { _, err := r.resolveByMode(owner, leader, clients, "cn"); canceled <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("round did not start")
	}
	type response struct {
		m   *dns.Msg
		err error
		id  uint16
	}
	replies := make(chan response, 2)
	for id := range uint16(2) {
		go func() {
			q := new(dns.Msg).SetQuestion("example.test.", dns.TypeA)
			q.Id = id
			m, err := r.resolveByMode(ctx, q, clients, "cn")
			replies <- response{m, err, id}
		}()
	}
	for {
		r.aggregateCacheMu.RLock()
		f := r.aggregateWarmup[key]
		joined := f != nil && f.waiters == 3
		r.aggregateCacheMu.RUnlock()
		if joined {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("followers did not join")
		}
		time.Sleep(time.Millisecond)
	}
	leave()
	if err := <-canceled; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner: %v", err)
	}
	close(release)
	for range 2 {
		v := <-replies
		if v.err != nil || v.m == nil || v.m.Id != v.id || v.m.Question[0].Name != "example.test." || v.m.Answer[0].Header().Ttl != 5 {
			t.Fatalf("wrong follower reply: %+v", v)
		}
		v.m.Answer[0].Header().Ttl = 999
	}
	if calls.Load() != 1 {
		t.Fatalf("got %d upstream calls", calls.Load())
	}
}

func TestEquivalentFlightKeys(t *testing.T) {
	q := new(dns.Msg).SetQuestion("eXample.test.", dns.TypeA)
	q.SetEdns0(1232, false)
	base := buildAggregateCacheKey(q, "cn")
	if base == "" {
		t.Fatal("ordinary query not shareable")
	}
	other := q.Copy()
	other.Id++
	other.Question[0].Name = "EXAMPLE.test."
	if buildAggregateCacheKey(other, "cn") != base {
		t.Fatal("unnecessary separation by ID or case")
	}
	if buildAggregateCacheKey(q, "overseas") == base {
		t.Fatal("merged routing groups")
	}
	for name, change := range map[string]func(*dns.Msg){"type": func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeAAAA }, "class": func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS }, "dnssec": func(m *dns.Msg) { m.IsEdns0().SetDo() }, "cd": func(m *dns.Msg) { m.CheckingDisabled = true }, "rd": func(m *dns.Msg) { m.RecursionDesired = false }, "size": func(m *dns.Msg) { m.IsEdns0().SetUDPSize(512) }, "ecs": func(m *dns.Msg) {
		m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)}}
	}} {
		m := q.Copy()
		change(m)
		if buildAggregateCacheKey(m, "cn") == base {
			t.Errorf("did not separate %s", name)
		}
	}
	q.SetTsig("example.test.", dns.HmacSHA256, 300, 1)
	if buildAggregateCacheKey(q, "cn") != "" {
		t.Fatal("signed query shareable")
	}
}
