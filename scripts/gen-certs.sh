#!/usr/bin/env bash
# The local stand's certificate.
#
# It is not in the repository: a private key in open code is a bad sign, and the
# certificate itself is self-signed and single-use. The tests and the stands
# expect it in capture/certs/, so this is where it is made.
#
# The SAN names: localhost and 127.0.0.1, which the tests go to; www.example.com
# is needed by the redirect and proxy checks.
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
  echo "certificate already present: $dir"
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
  echo "EC did not work, falling back to RSA: $(openssl version)"
  openssl req -x509 -newkey rsa:2048 -days 3650 \
    -nodes -keyout "$dir/tls.key" -out "$dir/tls.crt" -subj "/CN=localhost" \
    -addext "$san"
fi

echo "created: $dir/tls.crt"
