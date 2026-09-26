package profile

// ConnPolicy is how a browser family spends connections — something a CDN
// sees before it sees a single header: how many TLS handshakes a page's
// burst of requests costs, which hosts share a connection, which requests a
// browser keeps apart. Every field is measured on the hcapture -subres stand
// (Chrome 153, Firefox 156; docs/STAGE21-RESULTS.md); a family with no
// measurement gets the zero policy, which is the library's behaviour before
// 0.13: a connection per request until one is pooled, nothing shared across
// names, nothing kept apart.
type ConnPolicy struct {
	// Attempts is how many connections a burst of parallel first requests
	// to a host opens at most while the host's protocol is unknown. A
	// browser cannot know whether the server speaks HTTP/2 before the first
	// handshake answers, so it races a few; the first to come up as HTTP/2
	// carries every request, and the rest are closed. Chrome 153 opened
	// min(n, 4) for n parallel fetches (1, 2, 4 and 4 for 1, 2, 4 and 16;
	// 3 or 4 for 8, by timing), Firefox 156 min(n, 6). Zero keeps the old
	// behaviour: one attempt per request.
	Attempts int
	// SpareBeforePreface says how a spare that came up as HTTP/2 is closed:
	// true — right after the TLS handshake, before the HTTP/2 preface
	// (Chrome: the stand read EOF where the preface was due); false — after
	// the preface and SETTINGS, with GOAWAY (Firefox). Either way attempts
	// still in their handshake are abandoned.
	SpareBeforePreface bool
	// IPPooling lets an HTTP/2 connection serve another name that resolves
	// to the same address when the connection's certificate covers that
	// name and was verified, as Chrome does (api.a.localhost rode on the
	// connection www.a.localhost opened, and later on one d.localhost
	// opened). Chrome refuses a wildcard over a registry-controlled name
	// for this: *.localhost did not pool b.localhost. Firefox pooled nothing
	// on the stand, but the stand's certificate is trusted there through an
	// override, which switches Firefox's coalescing off; its rule is not
	// measured and is left off.
	IPPooling bool
	// SplitCredentials keeps requests made without credentials on
	// connections of their own (Chrome's privacy mode): an <img crossorigin>
	// to another site and a plain <img> to the same host went on two
	// connections, as did fetch with credentials "omit" and "include".
	// Firefox put both on one.
	SplitCredentials bool
	// PartitionBySite keys connections by the top-level site of the page a
	// request is made from, and by whether the request is a cross-site
	// frame (Chrome's NetworkAnonymizationKey): an <iframe> to a host
	// already connected went on a new connection.
	PartitionBySite bool
}

// ConnPolicyFor returns the family's connection policy.
func ConnPolicyFor(family string) ConnPolicy {
	switch family {
	case "chrome", "chromium", "edge", "yandex", "opera", "brave", "samsung":
		return ConnPolicy{Attempts: 4, SpareBeforePreface: true, IPPooling: true,
			SplitCredentials: true, PartitionBySite: true}
	case "firefox", "tor":
		return ConnPolicy{Attempts: 6}
	}
	return ConnPolicy{}
}
