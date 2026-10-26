package dnsrr

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ednsSize is the UDP payload size the query offers: the value DNS Flag Day
// 2020 settled on, which Chrome's resolver uses.
const ednsSize = 1232

func newID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func buildQuery(id uint16, name string, t dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, errFormat("name", err)
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// knownKeys are the SvcParamKeys a browser understands; a record that makes
// another one mandatory is skipped (RFC 9460, section 8).
var knownKeys = map[dnsmessage.SVCParamKey]bool{
	dnsmessage.SVCParamMandatory: true, dnsmessage.SVCParamALPN: true, dnsmessage.SVCParamNoDefaultALPN: true,
	dnsmessage.SVCParamPort: true, dnsmessage.SVCParamIPv4Hint: true, dnsmessage.SVCParamECH: true,
	dnsmessage.SVCParamIPv6Hint: true,
}

// parseHTTPS reads the HTTPS records of name out of an answer, following a
// CNAME chain inside it, by Chrome's rules (net/dns/dns_response_result_
// extractor.cc, 155): an AliasMode record anywhere clears the answer, since
// Chrome does not follow one; a ServiceMode record is kept when its target —
// the owner for "." — is host or, without a port prefix, the end of the CNAME
// chain, when its port is the request's, and when it leaves a protocol to
// speak; http/1.1 joins its ALPN unless no-default-alpn says otherwise, and
// when no record allows that default nothing is kept. alias is unused and
// always empty: kept for the resolver's loop, which never follows one.
func parseHTTPS(msg []byte, name, host string, port int) (services []Service, alias string, ttl time.Duration, err error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, "", 0, errFormat("header", err)
	}
	if !h.Response {
		return nil, "", 0, errors.New("dns: not a response")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, "", 0, errFormat("question", err)
	}
	ttl = maxTTL
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		if err := p.SkipAllAnswers(); err != nil {
			return nil, "", negativeTTL, nil
		}
		return nil, "", negativeTTLFrom(&p), nil
	default:
		return nil, "", 0, errors.New("dns: the server answered " + h.RCode.String())
	}

	type rec struct {
		owner string
		r     dnsmessage.HTTPSResource
		ttl   uint32
	}
	cnames := map[string]string{}
	var recs []rec
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, "", 0, errFormat("answer", err)
		}
		owner := strings.ToLower(rh.Name.String())
		switch rh.Type {
		case dnsmessage.TypeCNAME:
			c, err := p.CNAMEResource()
			if err != nil {
				return nil, "", 0, errFormat("cname", err)
			}
			cnames[owner] = strings.ToLower(c.CNAME.String())
			ttl = min(ttl, time.Duration(rh.TTL)*time.Second)
		case dnsmessage.TypeHTTPS:
			r, err := p.HTTPSResource()
			if err != nil {
				return nil, "", 0, errFormat("https", err)
			}
			recs = append(recs, rec{owner, r, rh.TTL})
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, "", 0, errFormat("answer", err)
			}
		}
	}
	// The records belong to the end of the CNAME chain.
	owner := strings.ToLower(name)
	for i := 0; i < maxAliases; i++ {
		next, ok := cnames[owner]
		if !ok {
			break
		}
		owner = next
	}
	found := false
	host = strings.ToLower(strings.TrimSuffix(host, ".")) + "."
	defaultALPN := false
	for _, r := range recs {
		if r.owner != owner {
			continue
		}
		found = true
		ttl = min(ttl, time.Duration(r.ttl)*time.Second)
		if r.r.Priority == 0 {
			return nil, "", ttl, nil // AliasMode: Chrome keeps nothing
		}
		target := strings.ToLower(r.r.Target.String())
		if target == "." {
			target = owner
		}
		// The target must be where the addresses are: host itself, or the end
		// of its CNAME chain — which a "_port._https" owner never is.
		if target != host && (target != owner || strings.HasPrefix(owner, "_")) {
			continue
		}
		s, ok := service(&r.r.SVCBResource)
		if !ok || (s.Port != 0 && int(s.Port) != port) {
			continue
		}
		if !s.NoDefaultALPN {
			defaultALPN = true
			if !contains(s.ALPN, "http/1.1") {
				s.ALPN = append(s.ALPN, "http/1.1")
			}
		}
		if len(s.ALPN) == 0 {
			continue
		}
		services = append(services, s)
	}
	if !found {
		ttl = negativeTTLFrom(&p)
	}
	if !defaultALPN {
		services = nil
	}
	sort.SliceStable(services, func(i, j int) bool { return services[i].Priority < services[j].Priority })
	return services, "", ttl, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func service(r *dnsmessage.SVCBResource) (Service, bool) {
	s := Service{Priority: r.Priority}
	if v, ok := r.GetParam(dnsmessage.SVCParamMandatory); ok {
		for i := 0; i+1 < len(v); i += 2 {
			if !knownKeys[dnsmessage.SVCParamKey(binary.BigEndian.Uint16(v[i:]))] {
				return s, false
			}
		}
	}
	if v, ok := r.GetParam(dnsmessage.SVCParamALPN); ok {
		for i := 0; i < len(v); {
			n := int(v[i])
			if i+1+n > len(v) {
				return s, false
			}
			s.ALPN = append(s.ALPN, string(v[i+1:i+1+n]))
			i += 1 + n
		}
	}
	_, s.NoDefaultALPN = r.GetParam(dnsmessage.SVCParamNoDefaultALPN)
	if v, ok := r.GetParam(dnsmessage.SVCParamPort); ok && len(v) == 2 {
		s.Port = binary.BigEndian.Uint16(v)
	}
	if v, ok := r.GetParam(dnsmessage.SVCParamECH); ok && len(v) > 0 {
		s.ECH = append([]byte(nil), v...)
	}
	return s, true
}

// negativeTTLFrom is how long "nothing here" may be kept: the SOA's minimum
// in the authority section (RFC 2308), the default without one.
func negativeTTLFrom(p *dnsmessage.Parser) time.Duration {
	for {
		h, err := p.AuthorityHeader()
		if err != nil {
			return negativeTTL
		}
		if h.Type != dnsmessage.TypeSOA {
			if p.SkipAuthority() != nil {
				return negativeTTL
			}
			continue
		}
		soa, err := p.SOAResource()
		if err != nil {
			return negativeTTL
		}
		return time.Duration(min(h.TTL, soa.MinTTL)) * time.Second
	}
}
