#!/usr/bin/env bash
# Сертификат локального стенда.
#
# В репозиторий он не входит: приватный ключ в открытом коде — плохая примета,
# а сам сертификат самоподписанный и одноразовый. Тесты и стенды ждут его
# в capture/certs/, поэтому здесь он и создаётся.
#
# Имена в SAN: localhost и 127.0.0.1 — по ним ходят тесты; www.example.com
# нужен проверкам редиректов и прокси.
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/capture/certs"
mkdir -p "$dir"

if [ -f "$dir/tls.crt" ] && [ -f "$dir/tls.key" ]; then
  echo "сертификат уже есть: $dir"
  exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout "$dir/tls.key" -out "$dir/tls.crt" -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,DNS:www.example.com,IP:127.0.0.1" \
  2>/dev/null

echo "создан: $dir/tls.crt"
