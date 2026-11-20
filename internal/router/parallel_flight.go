package router

import (
	"context"
	"time"

	"doh-autoproxy/internal/client"
	"github.com/miekg/dns"
)

// The cache and active rounds share a key and mutex: a miss must either join
// an existing round or become its owner, never slip between lookup and publish.
type aggregateFlight struct {
	ready     chan struct{}
	cancel    context.CancelFunc
	waiters   int
	refresh   bool
	published bool
	first     *dns.Msg // immutable after ready closes
	err       error
}

// Use the DNS wire request minus the transaction ID and question-name case.
// This also separates EDNS flags, subnet prefixes, UDP sizes and option data.
func buildAggregateCacheKey(req *dns.Msg, group string) string {
	if req == nil || req.Response || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 || len(req.Answer) != 0 || len(req.Ns) != 0 {
		return ""
	}
	switch req.Question[0].Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeTKEY:
		return ""
	}
	for _, rr := range req.Extra {
		if _, ok := rr.(*dns.OPT); !ok {
			return ""
		}
	}
	m := *req
	q := req.Question[0]
	q.Name = dns.CanonicalName(q.Name)
	m.Question = []dns.Question{q}
	m.Id = 0
	m.Compress = false
	var buf [512]byte
	wire, err := m.PackBuffer(buf[:])
	if err != nil {
		return ""
	}
	return group + "\x00" + string(wire)
}

func copyReplyFor(m, req *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}
	out := m.Copy()
	out.Id = req.Id
	if len(out.Question) == 1 {
		out.Question[0] = req.Question[0]
	}
	return out
}

func (r *Router) resolveByMode(ctx context.Context, req *dns.Msg, clients []client.DNSClient, group string) (*dns.Msg, error) {
	if !r.parallelReturn {
		return client.RaceResolve(ctx, req, clients)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := buildAggregateCacheKey(req, group)
	if key == "" { // Never replay signed or nonstandard messages to another caller.
		m, err := client.RaceResolve(ctx, req, clients)
		r.prepareFirst(m)
		setRequestReturnMode(ctx, "race-first")
		return m, err
	}
	r.aggregateCacheMu.Lock()
	now := time.Now()
	entry := r.aggregateCache[key]
	f := r.aggregateWarmup[key]
	if entry.resp != nil && now.Before(entry.expiresAt) {
		entry.hitCount++
		entry.expiresAt = now.Add(r.parallelAggregateCacheTTLForResponse(entry.resp))
		refresh := f == nil && entry.hitCount >= hotAggregateRefreshThreshold && now.Sub(entry.lastHotRefresh) >= hotAggregateRefreshMinInterval
		if refresh {
			entry.lastHotRefresh = now
			r.startFlightLocked(ctx, key, req, clients, true)
		}
		r.aggregateCache[key] = entry
		r.aggregateCacheMu.Unlock()
		if refresh && r.logger != nil {
			r.logger.RecordHotRefreshTrigger()
		}
		setRequestReturnMode(ctx, "aggregate-cache")
		return copyReplyFor(entry.resp, req), nil
	}
	if entry.resp != nil {
		delete(r.aggregateCache, key)
	}
	if f == nil {
		f = r.startFlightLocked(ctx, key, req, clients, false)
	}
	f.waiters++
	r.aggregateCacheMu.Unlock()
	select {
	case <-f.ready:
		setRequestReturnMode(ctx, "race-first")
		return copyReplyFor(f.first, req), f.err
	case <-ctx.Done():
		r.aggregateCacheMu.Lock()
		f.waiters--
		if f.waiters == 0 && !f.refresh && !f.published && r.aggregateWarmup[key] == f {
			delete(r.aggregateWarmup, key)
			f.cancel()
		}
		r.aggregateCacheMu.Unlock()
		return nil, ctx.Err()
	}
}

func (r *Router) prepareFirst(m *dns.Msg) {
	if m != nil {
		capResponseTTL(m, uint32(r.parallelWarmCacheTTLSeconds()))
		if r.parallelSingleRecordPerType() {
			client.TrimToSingleRecordPerType(m)
		}
	}
}

func (r *Router) startFlightLocked(parent context.Context, key string, req *dns.Msg, clients []client.DNSClient, refresh bool) *aggregateFlight {
	var ctx context.Context
	var cancel context.CancelFunc
	if refresh {
		ctx, cancel = context.WithTimeout(context.Background(), r.parallelAggregateCacheTTLForResponse(nil))
	} else {
		ctx, cancel = context.WithCancel(context.WithoutCancel(parent))
	}
	f := &aggregateFlight{ready: make(chan struct{}), cancel: cancel, refresh: refresh}
	r.aggregateWarmup[key] = f
	go r.collectFlight(ctx, key, f, req.Copy(), clients)
	return f
}

func (r *Router) collectFlight(ctx context.Context, key string, f *aggregateFlight, req *dns.Msg, clients []client.DNSClient) {
	defer f.cancel()
	resp, err := client.AggregateResolve(ctx, req, clients, r.parallelAggregateTTLStrategy(), func(m *dns.Msg, err error) {
		r.prepareFirst(m)
		r.aggregateCacheMu.Lock()
		f.first, f.err, f.published = m, err, true
		close(f.ready)
		r.aggregateCacheMu.Unlock()
	})
	ok := err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0
	r.aggregateCacheMu.Lock()
	// The last waiter may have canceled and a replacement round already started.
	if r.aggregateWarmup[key] == f {
		if ok {
			r.aggregateCache[key] = aggregateCacheEntry{resp: resp, expiresAt: time.Now().Add(r.parallelAggregateCacheTTLForResponse(resp)), lastHotRefresh: r.aggregateCache[key].lastHotRefresh}
		}
		delete(r.aggregateWarmup, key)
	}
	r.aggregateCacheMu.Unlock()
	if r.logger != nil {
		r.logger.RecordAggregateWarmup(ok)
	}
}
