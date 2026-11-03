package client

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Brave's Accept-Language farbling: the first language and its base
// ("ru-RU,ru"), then a weight from ;q=0.5 to ;q=0.9 picked by a generator
// seeded with the site and a per-session key
// (browser/net/brave_reduce_language_network_delegate_helper.cc,
// FarbleAcceptLanguageHeader and kFakeQValues). So the weight is one per
// site for a session, and differs between sites and sessions: measured on
// Brave 1.98.63, ru-RU,ru;q=0.5 on one run of the stand and q=0.6 on the
// next. The profile carries one of the values; the session writes the site's.

var braveWeight = regexp.MustCompile(`;q=0\.[5-9]$`)

// farbleAcceptLanguage rewrites the weight of a Brave profile's
// Accept-Language for the site of the request's page. A value the caller
// set itself, or one not in Brave's shape, is left as it is.
func (s *Session) farbleAcceptLanguage(built []headerKV, r *Request, u *url.URL) {
	if s.profile.Family() != "brave" || u == nil || requestSets(r, "accept-language") ||
		s.sessionSets(r, "accept-language") {
		return
	}
	site := u.Hostname()
	if top := s.topLevelFor(r, u); top != nil {
		site = top.Hostname()
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(site); err == nil {
		site = d
	}
	for i := range built {
		if !strings.EqualFold(built[i].Key, "accept-language") || !braveWeight.MatchString(built[i].Value) {
			continue
		}
		k := (blinkHash(strings.ToLower(site)) + s.hintSalt(true)*7919) % 5
		built[i].Value = braveWeight.ReplaceAllString(built[i].Value, ";q=0."+strconv.Itoa(5+int(k)))
	}
}
