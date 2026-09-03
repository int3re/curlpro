package h3

// Константы, перенесённые из серверной части uquic/http3.
//
// Пакет вендорится ради контроля над отпечатком, а серверный код нам не нужен;
// эти определения жили там же и требуются клиенту.

// NextProtoH3 — ALPN-протокол, согласуемый при рукопожатии, для QUIC v1 и v2.
const NextProtoH3 = "h3"

// Типы однонаправленных потоков HTTP/3 (RFC 9114, раздел 6.2).
const (
	streamTypeControlStream      = 0
	streamTypePushStream         = 1
	streamTypeQPACKEncoderStream = 2
	streamTypeQPACKDecoderStream = 3
)

// settingQPACKMaxTableCapacity — SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204, 5).
// Значение берётся из профиля (AdditionalSettings) и задаёт ёмкость нашей
// динамической таблицы.
const settingQPACKMaxTableCapacity = 0x01
