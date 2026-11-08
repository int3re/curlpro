package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/curlpro/curlpro/internal/client"
	"github.com/curlpro/curlpro/internal/wireprofile"
)

// fromWireJSON is curlpro_profile_from_wire's argument: what a client sent,
// base64, and the profile the result stands on.
type fromWireJSON struct {
	Name    string `json:"name"`
	BasedOn string `json:"based_on"`
	// ClientHello: the TLS record, or the handshake message — or a list of
	// the client's hellos on several connections, the first one the
	// profile's (their extension order tells permute_extensions).
	ClientHello json.RawMessage `json:"client_hello"`
	// H2: one connection's bytes after the handshake — the preface and the
	// frames — or a list of connections'.
	H2 json.RawMessage `json:"h2"`
	// QUICInitial: the client's first datagrams.
	QUICInitial []string `json:"quic_initial"`
	// H3Control: the client's HTTP/3 control stream.
	H3Control string `json:"h3_control"`
}

func decodeB64(field, s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if b, err2 := base64.RawStdEncoding.DecodeString(s); err2 == nil {
			return b, nil
		}
		return nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("%s: not base64: %w", field, err))
	}
	return b, nil
}

// curlpro_profile_from_wire builds a profile from what a client sent — its
// ClientHello, its HTTP/2 preface, frames and header blocks, its QUIC
// Initial, its HTTP/3 control stream — as the profile object session_new
// takes: {"profile": {…}, "notes": […]}. Only what the bytes show is set;
// based_on supplies the rest, and the notes say what could not be told
// (0.36).
//
//export curlpro_profile_from_wire
func curlpro_profile_from_wire(wire *C.char) (out *C.char) {
	defer recoverInto(&out)
	var w fromWireJSON
	if err := json.Unmarshal([]byte(C.GoString(wire)), &w); err != nil {
		return respond(nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("parsing profile_from_wire: %w", err)))
	}
	var in wireprofile.Input
	var err error
	if len(w.ClientHello) > 0 && string(w.ClientHello) != "null" {
		var hellos []string
		var one string
		if json.Unmarshal(w.ClientHello, &one) == nil {
			hellos = []string{one}
		} else if err := json.Unmarshal(w.ClientHello, &hellos); err != nil || len(hellos) == 0 {
			return respond(nil, client.CodeError(client.CodeConfiguration,
				fmt.Errorf("client_hello: a base64 string or a list of them")))
		}
		for i, h := range hellos {
			b, err := decodeB64(fmt.Sprintf("client_hello[%d]", i), h)
			if err != nil {
				return respond(nil, err)
			}
			if i == 0 {
				in.ClientHello = b
			} else {
				in.MoreClientHellos = append(in.MoreClientHellos, b)
			}
		}
	}
	if len(w.H2) > 0 && string(w.H2) != "null" {
		var conns []string
		var one string
		if json.Unmarshal(w.H2, &one) == nil {
			conns = []string{one}
		} else if err := json.Unmarshal(w.H2, &conns); err != nil {
			return respond(nil, client.CodeError(client.CodeConfiguration,
				fmt.Errorf("h2: a base64 string or a list of them")))
		}
		for i, c := range conns {
			b, err := decodeB64(fmt.Sprintf("h2[%d]", i), c)
			if err != nil {
				return respond(nil, err)
			}
			in.H2 = append(in.H2, b)
		}
	}
	for i, d := range w.QUICInitial {
		b, err := decodeB64(fmt.Sprintf("quic_initial[%d]", i), d)
		if err != nil {
			return respond(nil, err)
		}
		in.QUICInitial = append(in.QUICInitial, b)
	}
	if w.H3Control != "" {
		if in.H3Control, err = decodeB64("h3_control", w.H3Control); err != nil {
			return respond(nil, err)
		}
	}
	if len(in.ClientHello)+len(in.H2)+len(in.QUICInitial)+len(in.H3Control) == 0 {
		return respond(nil, client.CodeError(client.CodeConfiguration,
			fmt.Errorf("profile_from_wire: nothing given (client_hello, h2, quic_initial, h3_control)")))
	}
	res, err := wireprofile.Build(in)
	if err != nil {
		return respond(nil, client.CodeError(client.CodeConfiguration, err))
	}
	p := res.Profile
	p.Name = w.Name
	if p.Name == "" {
		p.Name = "from-wire"
	}
	p.BasedOn = w.BasedOn
	// The result must be what session_new takes — on its parent, or alone.
	// What it lacks then is said, not refused: a caller may add it.
	notes := res.Notes
	data, err := json.Marshal(p)
	if err != nil {
		return respond(nil, err)
	}
	if _, err := registry.ResolveInline(data); err != nil {
		why := strings.TrimPrefix(err.Error(), "parsing profile: ")
		if p.BasedOn != "" {
			return respond(nil, client.CodeError(client.CodeConfiguration,
				fmt.Errorf("the profile on %s: %s", p.BasedOn, why)))
		}
		notes = append(notes, "not yet a profile session_new takes: "+why)
	}
	if notes == nil {
		notes = []string{}
	}
	return respond(map[string]any{"profile": p, "notes": notes}, nil)
}
