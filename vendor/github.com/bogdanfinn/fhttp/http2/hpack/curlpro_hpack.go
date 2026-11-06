package hpack

// IndexMode is how a field goes when the tables hold no exact match for it
// (curlpro: a browser's encoder chooses by the name).
type IndexMode uint8

const (
	// IndexDefault leaves the choice to the encoder: index what fits.
	IndexDefault IndexMode = iota
	// IndexIncremental: "Literal Header Field with Incremental Indexing".
	IndexIncremental
	// IndexWithout: "Literal Header Field without Indexing".
	IndexWithout
	// IndexNever: "Literal Header Field Never Indexed".
	IndexNever
)

// SetIndexPolicy makes the encoder ask policy for each field's
// representation; nil restores its own.
func (e *Encoder) SetIndexPolicy(policy func(name string) IndexMode) {
	e.curlproPolicy = policy
}

// SetStaticNameFirst makes a literal take its name from the first entry of
// the static table that has it — :method 2, :path 4, :scheme 6 — as
// Chrome's encoder (QUICHE) does; Go's takes the last (3, 5, 7).
func (e *Encoder) SetStaticNameFirst(on bool) { e.curlproFirstName = on }

var curlproFirstStatic = func() map[string]uint64 {
	m := make(map[string]uint64, len(staticTableEntries))
	for i, f := range staticTableEntries {
		if _, ok := m[f.Name]; !ok {
			m[f.Name] = uint64(i + 1)
		}
	}
	return m
}()

// curlproName is the name index a literal goes with.
func (e *Encoder) curlproName(f HeaderField, idx uint64, match bool) uint64 {
	if !e.curlproFirstName || match || idx == 0 || idx > uint64(staticTable.len()) {
		return idx
	}
	if first, ok := curlproFirstStatic[f.Name]; ok {
		return first
	}
	return idx
}

// curlproMode applies the policy: whether the field goes into the dynamic
// table, and whether it is marked never indexed.
func (e *Encoder) curlproMode(f HeaderField, indexing bool) (bool, bool) {
	if e.curlproPolicy == nil || f.Sensitive {
		return indexing, f.Sensitive
	}
	switch e.curlproPolicy(f.Name) {
	case IndexWithout:
		return false, false
	case IndexNever:
		return false, true
	}
	return indexing, false
}
