package router

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"doh-autoproxy/internal/client"
	"doh-autoproxy/internal/config"
	"github.com/miekg/dns"
)

type upstreamFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f upstreamFunc) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return f(ctx, req)
}

func TestParallelRoundOwnsUnmodifiedAnswers(t *testing.T) {
	cfg := &config.Config{ParallelReturn: config.ParallelReturnConfig{SingleRecordPerType: true, WarmCacheTTL: 5}}
	r := NewRouterWithMode(cfg, nil, nil, true)
	q := new(dns.Msg).SetQuestion("warm.example.", dns.TypeA)
	key := buildAggregateCacheKey(q, "cn")
	release := make(chan struct{})
	var calls atomic.Int32
	clients := []client.DNSClient{
		upstreamFunc(func(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
			calls.Add(1)
			m := newAResp(q.Question[0].Name, "192.0.2.1", 120)
			m.Answer = append(m.Answer, newAResp(q.Question[0].Name, "192.0.2.2", 120).Answer...)
			return m, nil
		}),
		upstreamFunc(func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
			calls.Add(1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return newAResp(q.Question[0].Name, "192.0.2.3", 120), nil
			}
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	first, err := r.resolveByMode(ctx, q, clients, "cn")
	cancel() // The HTTP request has finished; aggregation must survive this.
	close(release)
	if err != nil || len(first.Answer) != 1 || first.Answer[0].Header().Ttl != 5 {
		t.Fatalf("bad first response: %v, %v", first, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.aggregateCacheMu.RLock()
		m := r.aggregateCache[key].resp
		r.aggregateCacheMu.RUnlock()
		if m != nil {
			if len(m.Answer) != 3 || calls.Load() != 2 {
				t.Fatalf("got %d records from %d calls", len(m.Answer), calls.Load())
			}
			for _, rr := range m.Answer {
				if rr.Header().Ttl != 120 {
					t.Fatalf("foreground TTL leaked: %v", rr)
				}
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("cache never received the slow answer")
}

func TestParallelRoundCanceledBeforeFirstReply(t *testing.T) {
	r := NewRouterWithMode(&config.Config{}, nil, nil, true)
	started, stopped := make(chan struct{}), make(chan struct{})
	c := upstreamFunc(func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.resolveByMode(ctx, new(dns.Msg).SetQuestion("cancel.example.", dns.TypeA), []client.DNSClient{c}, "cn")
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("foreground did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("upstream was not canceled")
	}
}
