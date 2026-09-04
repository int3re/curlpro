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

# Git Bash (MSYS) rewrites an argument that looks like a Unix path, so
# -subj "/CN=localhost" reached openssl as "C:/Program Files/Git/CN=localhost"
# and the script failed on the maintainer's own machine. Only that one
# argument is excluded: the file paths below are POSIX and do need the
# conversion, since openssl there is a native Windows binary.
# The variable means nothing on Linux and macOS and costs nothing there.
export MSYS2_ARG_CONV_EXCL='/CN='

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/capture/certs"
mkdir -p "$dir"

if [ -f "$dir/tls.crt" ] && [ -f "$dir/tls.key" ]; then
  echo "сертификат уже есть: $dir"
  exit 0
fi

# EC first, RSA as a fallback. On the macOS runner /usr/bin/openssl is
# LibreSSL, whose -pkeyopt handling differs between versions. The key type
# means nothing to the stand, while a CI that cannot produce a certificate
# stops every test that needs TLS.
san="subjectAltName=DNS:localhost,DNS:*.localhost,DNS:www.example.com,IP:127.0.0.1"
if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout "$dir/tls.key" -out "$dir/tls.crt" -subj "/CN=localhost" \
  -addext "$san" 2>/dev/null
then
  echo "EC не вышел, беру RSA: $(openssl version)"
  openssl req -x509 -newkey rsa:2048 -days 3650 \
    -nodes -keyout "$dir/tls.key" -out "$dir/tls.crt" -subj "/CN=localhost" \
    -addext "$san"
fi

echo "создан: $dir/tls.crt"
