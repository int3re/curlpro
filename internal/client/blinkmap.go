package client

import (
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/curlpro/curlpro/internal/profile"
)

// Blink's request header map, reproduced to order what a page sends.
//
// A request a page makes — fetch, XHR, an image, a script — carries the
// headers Blink set on it in an HTTPHeaderMap: the page's own headers, the
// client hints, the User-Agent. That map is a WTF::HashMap keyed by
// DeprecatedCaseFoldingHash, and the network stack copies it into the request
// in iteration order, which is bucket order. So the place of every header in
// that cluster is a function of the whole set of names: a hint the site asks
// for, or a header of the page's own, moves its neighbours. Measured on
// Chrome 155 and 156 (docs/STAGE45-RESULTS.md): 88 requests of every kind,
// 25 to 27 names each, all where this model puts them; and Stage 19's Chrome
// 153 clusters, X-Api-Key and all.
//
// The hash is rapidhash over the name case-folded to UTF-16, its low 24 bits
// (StringHasher::ComputeHashAndMaskTop8Bits); the table starts at 8 buckets,
// doubles when half full, probes triangularly and rehashes in bucket order
// (hash_table.h). Blink hashes this way since StringHasher moved to rapidhash
// (main@1337378, Chrome 129); before it the layout was another.

const (
	rapidSeed = 0xbdd89aa982704029
	rapidS0   = 0x2d358dccaa6c78a5
	rapidS1   = 0x8bb84b93962eacc9
	rapidS2   = 0x4b33a62ed433d4a3
)

func rapidMix(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return lo ^ hi
}

// foldedName is a header name as CaseFoldingHashReader reads it: ASCII
// lowercased, every character widened to 16 bits.
type foldedName string

func (s foldedName) at(i int) uint64 {
	c := s[i]
	if 'A' <= c && c <= 'Z' {
		c += 'a' - 'A'
	}
	return uint64(c)
}

func (s foldedName) read64(i int) uint64 {
	return s.at(i) | s.at(i+1)<<16 | s.at(i+2)<<32 | s.at(i+3)<<48
}

func (s foldedName) read32(i int) uint64 {
	return s.at(i) | s.at(i+1)<<16
}

// blinkHash is DeprecatedCaseFoldingHash::GetHash of an ASCII name.
func blinkHash(name string) uint32 {
	s := foldedName(name)
	n := uint64(2 * len(s)) // bytes the reader produces
	seed := uint64(rapidSeed)
	seed ^= rapidMix(seed^rapidS0, rapidS1) ^ n
	var a, b uint64
	if n <= 16 {
		switch {
		case n >= 4:
			last := int(n-4) / 2
			a = s.read32(0)<<32 | s.read32(last)
			delta := int(((n & 24) >> (n >> 3)) / 2)
			b = s.read32(delta)<<32 | s.read32(last-delta)
		case n > 0:
			a = s.at(0)
		}
	} else {
		i, p := int(n), 0
		if i > 48 {
			see1, see2 := seed, seed
			for {
				seed = rapidMix(s.read64(p)^rapidS0, s.read64(p+4)^seed)
				see1 = rapidMix(s.read64(p+8)^rapidS1, s.read64(p+12)^see1)
				see2 = rapidMix(s.read64(p+16)^rapidS2, s.read64(p+20)^see2)
				p += 24
				i -= 48
				if i < 48 {
					break
				}
			}
			seed ^= see1 ^ see2
		}
		if i > 16 {
			seed = rapidMix(s.read64(p)^rapidS2, s.read64(p+4)^seed^rapidS1)
			if i > 32 {
				seed = rapidMix(s.read64(p+8)^rapidS2, s.read64(p+12)^seed)
			}
		}
		a = s.read64(p + (i-16)/2)
		b = s.read64(p + (i-8)/2)
	}
	a ^= rapidS1
	b ^= seed
	hi, lo := bits.Mul64(a, b)
	h := uint32(rapidMix(lo^rapidS0^n, hi^rapidS1)) & (1<<24 - 1)
	if h == 0 {
		h = 0x80000000 >> 8
	}
	return h
}

// blinkLayout returns names in the order Blink's map hands them out after
// they were inserted in the given order. A name met twice keeps its first
// place, as HashMap::Set keeps the bucket of the key it overwrites.
func blinkLayout(names []string) []string {
	var slots []string
	var hashes []uint32
	count := 0
	place := func(name string, h uint32) bool {
		mask := uint32(len(slots) - 1)
		i := h & mask
		for k := uint32(1); slots[i] != ""; k++ {
			if strings.EqualFold(slots[i], name) {
				return false
			}
			i = (i + k) & mask
		}
		slots[i] = name
		hashes[i] = h
		return true
	}
	rehash := func(size int) {
		old, oldHashes := slots, hashes
		slots, hashes = make([]string, size), make([]uint32, size)
		for i, name := range old {
			if name != "" {
				place(name, oldHashes[i])
			}
		}
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if slots == nil {
			rehash(8)
		}
		if place(name, blinkHash(name)) {
			count++
			if count*2 >= len(slots) {
				rehash(len(slots) * 2)
			}
		}
	}
	out := make([]string, 0, count)
	for _, name := range slots {
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// blinkMapFor says the profile's browser lays a page's request headers out
// through the rapidhash map: Chromium 129 and later, by the Chrome version
// its User-Agent carries (Edge and Opera write Chromium's there too).
func blinkMapFor(p *profile.Profile) bool {
	if !profile.Chromium(p.Family()) {
		return false
	}
	m := chromeMajor.FindStringSubmatch(p.Headers.UserAgent)
	n, _ := strconv.Atoi(m1(m))
	return n >= 129
}

// blinkLayouts caches layouts by their input: a session sends the same few
// sets over and over. It stops growing at a few thousand sets, so names a
// caller makes up per request do not turn it into a leak.
var (
	blinkLayouts     sync.Map
	blinkLayoutCount atomic.Int32
)

func cachedBlinkLayout(names []string) []string {
	key := strings.Join(names, "\x00")
	if v, ok := blinkLayouts.Load(key); ok {
		return v.([]string)
	}
	out := blinkLayout(names)
	if blinkLayoutCount.Add(1) <= 4096 {
		blinkLayouts.Store(key, out)
	}
	return out
}
