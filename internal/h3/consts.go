package h3

// Constants carried over from the server side of uquic/http3.
//
// The package is vendored for control over the fingerprint, and the server code
// is not needed; these definitions lived there and the client requires them.

// NextProtoH3 is the ALPN protocol negotiated during the handshake, for QUIC v1 and v2.
const NextProtoH3 = "h3"

// HTTP/3 unidirectional stream types (RFC 9114, section 6.2).
const (
	streamTypeControlStream      = 0
	streamTypePushStream         = 1
	streamTypeQPACKEncoderStream = 2
	streamTypeQPACKDecoderStream = 3
)

// settingQPACKMaxTableCapacity — SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204, 5).
// The value comes from the profile (AdditionalSettings) and sets the capacity of
// our dynamic table.
const settingQPACKMaxTableCapacity = 0x01
