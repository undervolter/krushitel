package cloudip

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Package cloudip resolves the Dahua P2P cloud endpoint with a hardcoded
// fallback pool, so the tool keeps working when the system resolver is dead
// (no reachable nameserver, wiped resolv.conf, captive portal, router DNS
// dropping UDP/53). DNS is still tried first and its answers are cached; the
// static list is used only when resolution fails or returns nothing.

const (
	// Server is the Dahua P2P cloud hostname used across the project.
	Server = "www.easy4ipcloud.com"
	// Port is the cloud UDP port (DHIP handshake, /online/p2psrv, relay alloc).
	Port = 8800
)

// FallbackIPs is a static snapshot of the A records for Server (2026-10-09).
// Refresh with: go run ./tools/dnsdump www.easy4ipcloud.com
var FallbackIPs = []string{
	"165.154.165.8",
	"165.154.165.15",
	"165.154.165.19",
	"165.154.165.21",
	"165.154.165.27",
	"165.154.165.33",
	"165.154.165.35",
	"165.154.165.37",
	"165.154.165.40",
	"165.154.165.41",
	"165.154.165.42",
	"165.154.165.43",
	"165.154.165.47",
	"165.154.165.48",
	"165.154.165.53",
	"165.154.165.79",
	"165.154.165.110",
	"165.154.165.154",
	"165.154.165.231",
	"165.154.165.252",
	"165.154.198.11",
}

const (
	dnsTimeout   = 3 * time.Second
	cacheTTL     = 10 * time.Minute
	fallbackKeep = time.Hour // serve a stale DNS pool this long before dropping to static
)

type pool struct {
	host    string
	port    int
	addrs   []*net.UDPAddr
	expires time.Time
}

var (
	mu      sync.Mutex
	cached  *pool
	rr      atomic.Uint64
	fromDNS atomic.Bool
)

// Addrs returns one UDP address per resolved IP: DNS first, static pool on
// failure. For the cloud hostname the result is never nil as long as
// FallbackIPs is non-empty; for any other host a dead resolver yields nil.
func Addrs(host string, port int) []*net.UDPAddr {
	host = trimPort(host)
	if port <= 0 {
		port = Port
	}

	mu.Lock()
	defer mu.Unlock()

	// Under the lock: many goroutines dial the cloud at once, so DNS must be
	// attempted once per cache window, not once per dial.
	if cached != nil && cached.host == host && cached.port == port {
		if time.Now().Before(cached.expires) {
			return cached.addrs
		}
		// Expired but recently good: prefer the known-good DNS result over the
		// static guess, and re-resolve in the background for the next call.
		if fromDNS.Load() && time.Now().Before(cached.expires.Add(fallbackKeep)) {
			cached.expires = time.Now().Add(cacheTTL)
			if rehydrateInFlight.CompareAndSwap(false, true) {
				go rehydrate(host, port)
			}
			return cached.addrs
		}
	}

	if addrs := dnsAddrs(host, port); len(addrs) > 0 {
		fromDNS.Store(true)
		cached = &pool{host: host, port: port, addrs: addrs, expires: time.Now().Add(cacheTTL)}
		return addrs
	}

	// Only the cloud hostname has a static pool; any other host must report the
	// real DNS failure instead of silently getting cloud IPs.
	fallback := staticAddrs(port)
	if !isCloudHost(host) {
		fallback = nil
	}

	fromDNS.Store(len(fallback) == 0)
	cached = &pool{host: host, port: port, addrs: fallback, expires: time.Now().Add(cacheTTL)}
	return cached.addrs
}

func isCloudHost(host string) bool {
	h := strings.ToLower(trimPort(host))
	return h == Server || h == "easy4ipcloud.com"
}

// rehydrateInFlight marks the background re-resolve so tests can wait it out.
var rehydrateInFlight atomic.Bool

func rehydrate(host string, port int) {
	defer rehydrateInFlight.Store(false)
	if addrs := dnsAddrs(host, port); len(addrs) > 0 {
		mu.Lock()
		cached = &pool{host: host, port: port, addrs: addrs, expires: time.Now().Add(cacheTTL)}
		fromDNS.Store(true)
		mu.Unlock()
	}
}

// Next returns one address from the pool, rotating round-robin so parallel
// workers spread across the cloud edge instead of hammering a single IP.
func Next(host string, port int) *net.UDPAddr {
	addrs := Addrs(host, port)
	if len(addrs) == 0 {
		return nil
	}
	return addrs[int(rr.Add(1))%len(addrs)]
}

// NextN returns n addresses, cycling when the pool is smaller than n.
func NextN(host string, port int, n int) []*net.UDPAddr {
	addrs := Addrs(host, port)
	if len(addrs) == 0 || n <= 0 {
		return nil
	}
	out := make([]*net.UDPAddr, 0, n)
	base := int(rr.Add(1))
	for i := 0; i < n; i++ {
		out = append(out, addrs[(base+i)%len(addrs)])
	}
	return out
}

// Alive reports whether the cloud endpoint looks usable. UDP reachability
// cannot be proven without sending traffic, so this only means "we have at
// least one address to try".
func Alive(host string) bool {
	return len(Addrs(host, Port)) > 0
}

// Static reports whether the pool currently in use came from the hardcoded
// list rather than DNS. Callers log a warning when it is true. Forced false for
// hosts without a static pool, where an empty result means a genuine failure.
func Static() bool {
	mu.Lock()
	defer mu.Unlock()
	if cached == nil || !isCloudHost(cached.host) {
		return false
	}
	return !fromDNS.Load()
}

// IPs returns the resolved v4 addresses, for scanners that dial per-IP.
func IPs(host string) []net.IP {
	addrs := Addrs(host, Port)
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			out = append(out, a.IP)
		}
	}
	return out
}

// Reset drops the cache. Tests use it; also useful after a network change.
func Reset() {
	mu.Lock()
	cached = nil
	fromDNS.Store(false)
	mu.Unlock()
	rehydrateInFlight.Store(false)
}

// dnsLookup is a variable so tests can simulate a dead resolver.
var dnsLookup = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// SetDNSForTest swaps the resolver used by this package and returns the old
// one, so tests can force the static-pool path. Pass nil to restore the system
// resolver.
func SetDNSForTest(fn func(context.Context, string) ([]net.IP, error)) func(context.Context, string) ([]net.IP, error) {
	prev := dnsLookup
	if fn == nil {
		fn = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		}
	}
	dnsLookup = fn
	Reset()
	return prev
}

func dnsAddrs(host string, port int) []*net.UDPAddr {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []*net.UDPAddr{{IP: v4, Port: port}}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	ips, err := dnsLookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	out := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, &net.UDPAddr{IP: v4, Port: port})
		}
	}
	return out
}

func staticAddrs(port int) []*net.UDPAddr {
	out := make([]*net.UDPAddr, 0, len(FallbackIPs))
	for _, s := range FallbackIPs {
		if ip := net.ParseIP(s).To4(); ip != nil {
			out = append(out, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	return out
}

func trimPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
