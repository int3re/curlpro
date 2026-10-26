// Command echstand measures a browser's Encrypted Client Hello against a
// stand of its own: a DNS-over-HTTPS server that publishes an HTTPS record
// with an ECH configuration, and a TLS server holding that configuration's
// key. It keeps the outer ClientHello of every connection, decrypts the inner
// one (RFC 9849, section 5.2: HPKE over ClientHelloOuterAAD), expands the
// extensions the inner one compressed into ech_outer_extensions, and writes
// both out — the inner hello is what a server that terminates ECH sees, and
// therefore part of the fingerprint.
//
// Chrome reaches the stand through its own secure-DNS settings, kept in the
// throwaway profile's Local State (dns_over_https.mode and .templates): no
// system setting changes. Firefox would need network.trr.* prefs; not done.
//
//	go run ./cmd/echstand -auto -json out.json
//	go run ./cmd/echstand -json out.json        # stand only; point a client at -doh
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	listen  = flag.String("listen", "127.0.0.1:8444", "the ECH-capable TLS server")
	dohAddr = flag.String("doh", "127.0.0.1:8053", "the DNS-over-HTTPS server")
	name    = flag.String("name", "ech-stand.test", "the name behind ECH (the inner SNI)")
	public  = flag.String("public", "public.ech-stand.test", "the ECH configuration's public_name (the outer SNI)")
	maxName = flag.Int("max-name", 0, "the configuration's maximum_name_length")
	certs   = flag.String("certs", "capture/certs", "directory holding tls.crt and tls.key")
	auto    = flag.Bool("auto", false, "launch the installed Chrome at the stand")
	browser = flag.String("browser", "", "the Chrome to launch (found by -auto when empty)")
	timeout = flag.Duration("timeout", 20*time.Second, "how long to wait")
	out     = flag.String("json", "", "where to write the measurement")
	netlog  = flag.String("netlog", "", "where Chrome writes its net log (--log-net-log)")
)

type conn struct {
	Outer        string   `json:"outer"`         // the ClientHello record, hex
	EncodedInner string   `json:"encoded_inner"` // EncodedClientHelloInner with its padding, hex
	Inner        string   `json:"inner"`         // the ClientHelloInner as the server rebuilt it, hex
	PayloadLen   int      `json:"payload_len"`
	Padding      int      `json:"padding"`
	OuterSNI     string   `json:"outer_sni"`
	InnerSNI     string   `json:"inner_sni"`
	Compressed   []uint16 `json:"compressed"` // ech_outer_extensions, in order
	Error        string   `json:"error,omitempty"`
}

type result struct {
	Config      string   `json:"ech_config_list"`
	MaxNameLen  int      `json:"max_name_len"`
	DNS         []string `json:"dns"`
	Connections []conn   `json:"connections"`
	Accepted    []bool   `json:"ech_accepted"`
	Requests    []string `json:"requests"`
}

var (
	mu  sync.Mutex
	res result
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	cert, err := tls.LoadX509KeyPair(filepath.Join(*certs, "tls.crt"), filepath.Join(*certs, "tls.key"))
	if err != nil {
		log.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	var id [1]byte
	rand.Read(id[:])
	cfg := echConfig(key.PublicKey().Bytes(), id[0], *public, uint8(*maxName))
	list := binary.BigEndian.AppendUint16(nil, uint16(len(cfg)))
	list = append(list, cfg...)
	res.Config, res.MaxNameLen = hex.EncodeToString(list), *maxName

	// The TLS server: ECH with our key, and the raw bytes of what arrives.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	srvCfg := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		NextProtos:               []string{"h2", "http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true}},
	}
	tlsLn := tls.NewListener(&teeListener{Listener: ln, key: key, cfg: cfg}, srvCfg)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var names []string
		for k := range r.Header {
			names = append(names, strings.ToLower(k))
		}
		mu.Lock()
		res.Requests = append(res.Requests, r.Proto+" "+r.Host+r.URL.Path)
		if r.TLS != nil {
			res.Accepted = append(res.Accepted, r.TLS.ECHAccepted)
		}
		mu.Unlock()
		io.WriteString(w, "<!doctype html><title>ech</title>ok")
	})}
	go srv.Serve(tlsLn)

	// The DoH server.
	_, port, _ := net.SplitHostPort(*listen)
	doh := &http.Server{Addr: *dohAddr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q []byte
		if r.Method == http.MethodGet {
			q, _ = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			q, _ = io.ReadAll(r.Body)
		}
		a, desc := answer(q, port, list)
		mu.Lock()
		res.DNS = append(res.DNS, desc)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(a)
	}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go func() {
		if err := doh.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	log.Printf("stand: https://%s:%s/ (ECH, public name %s), DoH https://%s/dns-query", *name, port, *public, *dohAddr)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *auto || *browser != "" {
		go launchChrome(ctx, cert, "https://"+*name+":"+port+"/")
	}
	// Two requests are enough: the first decides the connection, the favicon
	// shows whether a second one is made the same way.
	for ctx.Err() == nil {
		mu.Lock()
		n := len(res.Requests)
		mu.Unlock()
		if n >= 2 {
			time.Sleep(time.Second)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	srv.Close()
	doh.Close()
	mu.Lock()
	defer mu.Unlock()
	for i, c := range res.Connections {
		log.Printf("connection %d: outer SNI %q, inner SNI %q, payload %d, padding %d, compressed %v %s",
			i, c.OuterSNI, c.InnerSNI, c.PayloadLen, c.Padding, c.Compressed, c.Error)
	}
	log.Printf("requests %v, ECH accepted %v", res.Requests, res.Accepted)
	if *out != "" {
		b, _ := json.MarshalIndent(&res, "", " ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			log.Fatal(err)
		}
		log.Printf("written to %s", *out)
	}
}

func echConfig(pub []byte, id uint8, publicName string, maxName uint8) []byte {
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 8)
	c = binary.BigEndian.AppendUint16(c, 0x0001)
	c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256, AES-128-GCM
	c = binary.BigEndian.AppendUint16(c, 0x0001)
	c = binary.BigEndian.AppendUint16(c, 0x0003) // HKDF-SHA256, ChaCha20Poly1305
	c = append(c, maxName)
	c = append(c, byte(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0)
	out := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...)
}

// answer is the DoH reply: the stand's names at 127.0.0.1, its HTTPS record
// with the ECH configuration, nothing for the rest.
func answer(q []byte, port string, ech []byte) ([]byte, string) {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil, "bad query"
	}
	question, err := p.Question()
	if err != nil {
		return nil, "bad question"
	}
	qn := strings.ToLower(question.Name.String())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(question)
	b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
	https := *name + "."
	if port != "443" {
		https = "_" + port + "._https." + *name + "."
	}
	switch {
	case question.Type == dnsmessage.TypeA && (qn == *name+"." || qn == *public+"."):
		b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
	case question.Type == dnsmessage.TypeHTTPS && qn == https:
		// On a "_port._https" name the target must name the host (RFC 9460,
		// 9.1); Chrome leaves a record pointing at "." there unused.
		target := "."
		if port != "443" {
			target = *name + "."
		}
		b.HTTPSResource(rh, dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
			Priority: 1, Target: dnsmessage.MustNewName(target),
			Params: []dnsmessage.SVCParam{
				{Key: dnsmessage.SVCParamALPN, Value: []byte("\x02h2\x08http/1.1")},
				{Key: dnsmessage.SVCParamECH, Value: ech},
			}}})
	}
	out, _ := b.Finish()
	return out, question.Type.String() + " " + qn
}

// teeListener keeps the first TLS record of every connection.
type teeListener struct {
	net.Listener
	key *ecdh.PrivateKey
	cfg []byte
}

func (l *teeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &teeConn{Conn: c, l: l}, nil
}

type teeConn struct {
	net.Conn
	l    *teeListener
	buf  bytes.Buffer
	done bool
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.done && n > 0 {
		c.buf.Write(p[:n])
		b := c.buf.Bytes()
		if len(b) >= 5 && len(b) >= 5+int(binary.BigEndian.Uint16(b[3:5])) {
			c.done = true
			rec := append([]byte(nil), b[:5+int(binary.BigEndian.Uint16(b[3:5]))]...)
			m := decode(rec, c.l.key, c.l.cfg)
			mu.Lock()
			res.Connections = append(res.Connections, m)
			mu.Unlock()
		}
	}
	return n, err
}

// decode takes an outer ClientHello record apart and opens its ECH payload.
func decode(rec []byte, key *ecdh.PrivateKey, cfg []byte) conn {
	m := conn{Outer: hex.EncodeToString(rec)}
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x01 {
		m.Error = "not a ClientHello"
		return m
	}
	body := rec[9:] // the ClientHello structure: what ClientHelloOuterAAD is made of
	ch, err := parseHello(body)
	if err != nil {
		m.Error = err.Error()
		return m
	}
	m.OuterSNI = sni(ch.ext[0x0000])
	e, ok := ch.ext[0xfe0d]
	if !ok || len(e) < 1 || e[0] != 0 {
		m.Error = "no outer ECH extension"
		return m
	}
	kdfID, aeadID := binary.BigEndian.Uint16(e[1:]), binary.BigEndian.Uint16(e[3:])
	encLen := int(binary.BigEndian.Uint16(e[6:]))
	enc := e[8 : 8+encLen]
	payload := e[8+encLen+2:]
	m.PayloadLen = len(payload)

	// ClientHelloOuterAAD: the outer hello with the payload zeroed.
	aad := append([]byte(nil), body...)
	off := ch.extOff[0xfe0d] + 8 + encLen + 2
	for i := range payload {
		aad[off+i] = 0
	}
	priv, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		m.Error = err.Error()
		return m
	}
	kdf, _ := hpke.NewKDF(kdfID)
	aead, err := hpke.NewAEAD(aeadID)
	if err != nil {
		m.Error = err.Error()
		return m
	}
	info := append([]byte("tls ech\x00"), cfg...)
	r, err := hpke.NewRecipient(enc, priv, kdf, aead, info)
	if err != nil {
		m.Error = err.Error()
		return m
	}
	encoded, err := r.Open(aad, payload)
	if err != nil {
		m.Error = "open: " + err.Error()
		return m
	}
	m.EncodedInner = hex.EncodeToString(encoded)
	inner, compressed, padding, err := expand(encoded, ch)
	if err != nil {
		m.Error = err.Error()
		return m
	}
	m.Inner, m.Compressed, m.Padding = hex.EncodeToString(inner), compressed, padding
	if ih, err := parseHello(inner); err == nil {
		m.InnerSNI = sni(ih.ext[0x0000])
	}
	return m
}

type hello struct {
	sessionID []byte
	ext       map[uint16][]byte
	extOff    map[uint16]int // offset of the extension's data in the body
	order     []uint16
	extStart  int // offset of the extensions block (its length) in the body
	extEnd    int
}

func parseHello(b []byte) (*hello, error) {
	h := &hello{ext: map[uint16][]byte{}, extOff: map[uint16]int{}}
	i := 2 + 32
	if len(b) < i+1 {
		return nil, errors.New("short hello")
	}
	h.sessionID = b[i+1 : i+1+int(b[i])]
	i += 1 + int(b[i])
	i += 2 + int(binary.BigEndian.Uint16(b[i:]))
	i += 1 + int(b[i])
	h.extStart = i
	end := i + 2 + int(binary.BigEndian.Uint16(b[i:]))
	i += 2
	for i+4 <= end {
		t, n := binary.BigEndian.Uint16(b[i:]), int(binary.BigEndian.Uint16(b[i+2:]))
		h.ext[t], h.extOff[t] = b[i+4:i+4+n], i+4
		h.order = append(h.order, t)
		i += 4 + n
	}
	h.extEnd = end
	return h, nil
}

// expand turns an EncodedClientHelloInner into the ClientHelloInner: the
// outer session ID back in, ech_outer_extensions replaced by the outer
// extensions it names (RFC 9849, section 5.1), the padding cut off.
func expand(encoded []byte, outer *hello) ([]byte, []uint16, int, error) {
	in, err := parseHello(encoded)
	if err != nil {
		return nil, nil, 0, err
	}
	padding := len(encoded) - in.extEnd
	var exts []byte
	var compressed []uint16
	for _, t := range in.order {
		if t == 0xfd00 {
			v := in.ext[t]
			for j := 1; j+1 < 1+int(v[0])+1 && j+1 < len(v); j += 2 {
				ot := binary.BigEndian.Uint16(v[j:])
				compressed = append(compressed, ot)
				exts = binary.BigEndian.AppendUint16(exts, ot)
				exts = binary.BigEndian.AppendUint16(exts, uint16(len(outer.ext[ot])))
				exts = append(exts, outer.ext[ot]...)
			}
			continue
		}
		exts = binary.BigEndian.AppendUint16(exts, t)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(in.ext[t])))
		exts = append(exts, in.ext[t]...)
	}
	var b []byte
	b = append(b, encoded[:2+32]...)
	b = append(b, byte(len(outer.sessionID)))
	b = append(b, outer.sessionID...)
	i := 2 + 32 + 1 + int(encoded[2+32])
	b = append(b, encoded[i:in.extStart]...) // cipher suites, compression
	b = binary.BigEndian.AppendUint16(b, uint16(len(exts)))
	b = append(b, exts...)
	return b, compressed, padding, nil
}

func sni(v []byte) string {
	if len(v) < 5 {
		return ""
	}
	return string(v[5:])
}

func launchChrome(ctx context.Context, cert tls.Certificate, url string) {
	path := *browser
	if path == "" {
		for _, p := range []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			"/usr/bin/google-chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		log.Print("no Chrome found")
		return
	}
	dir, err := os.MkdirTemp("", "echstand-")
	if err != nil {
		log.Print(err)
		return
	}
	defer os.RemoveAll(dir)
	// Secure DNS through the stand, in this profile only.
	state := fmt.Sprintf(`{"dns_over_https":{"mode":"secure","templates":"https://%s/dns-query"}}`, *dohAddr)
	if err := os.WriteFile(filepath.Join(dir, "Local State"), []byte(state), 0o644); err != nil {
		log.Print(err)
		return
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	args := []string{"--headless=new", "--user-data-dir=" + dir, "--no-first-run",
		"--no-default-browser-check", "--ignore-certificate-errors-spki-list=" + base64.StdEncoding.EncodeToString(spki[:])}
	if *netlog != "" {
		args = append(args, "--log-net-log="+*netlog, "--net-log-capture-mode=Everything")
	}
	cmd := exec.CommandContext(ctx, path, append(args, url)...)
	log.Printf("browser: %s", path)
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		log.Printf("browser: %v", err)
	}
}
