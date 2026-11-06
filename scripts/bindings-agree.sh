#!/usr/bin/env bash
# Every binding must send the same fingerprint: the whole point of the library
# is that the profile, not the language, decides what goes on the wire.
#
# Each binding prints the offline JA4 of chrome-156-windows for
# https://example.com/ (no network); the Go package is the reference. A binding
# whose toolchain is missing is skipped locally and fails in CI
# (BINDINGS_STRICT=1), so a matrix runner cannot quietly drop a language.
#
#   CURLPRO_LIBRARY=$PWD/dist/libcurlpro.so scripts/bindings-agree.sh
set -u
cd "$(dirname "$0")/.."
root=$PWD
export CURLPRO_PROFILES="${CURLPRO_PROFILES:-$root/profiles}"
strict="${BINDINGS_STRICT:-0}"

if [ -z "${CURLPRO_LIBRARY:-}" ]; then
  echo "CURLPRO_LIBRARY is not set: build the library first (see docs/C-ABI.md)" >&2
  exit 2
fi
libdir=$(dirname "$CURLPRO_LIBRARY")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }

run_c() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) gcc -I include bindings/c/ja4.c "$CURLPRO_LIBRARY" -o "$work/ja4.exe" && cp "$CURLPRO_LIBRARY" "$work/" && "$work/ja4.exe" ;;  # the loader looks next to the exe
    *) cc -I include bindings/c/ja4.c -L"$libdir" -lcurlpro -Wl,-rpath,"$libdir" -o "$work/ja4" && "$work/ja4" ;;
  esac
}
run_go() { go run ./bindings/go/ja4; }
run_python() { PYTHONPATH=python python -c "
import os, curlpro
curlpro.load_profiles(os.environ['CURLPRO_PROFILES'])
with curlpro.Session('chrome-156-windows') as s:
    print(s.fingerprint('https://example.com/').ja4)"; }
run_dotnet() { dotnet run --project bindings/dotnet/Example -v q -nologo ${DOTNET_TFM:+-p:CurlproTfm=$DOTNET_TFM} -- --ja4; }
run_node() { (cd bindings/node && { [ -d node_modules/koffi ] || npm install --no-audit --no-fund --silent >/dev/null; } && node ja4.js); }
run_java() {
  javac --release 22 -d "$work/classes" $(find bindings/java/src/main/java -name '*.java') &&
    java --enable-native-access=ALL-UNNAMED -cp "$work/classes" bindings/java/examples/Ja4.java
}
run_rust() { cargo run --quiet --manifest-path bindings/rust/Cargo.toml --example ja4; }
run_php() { php -d ffi.enable=1 bindings/php/ja4.php; }

declare -A tool=([c]=cc [go]=go [python]=python [dotnet]=dotnet [node]=node [java]=javac [rust]=cargo [php]=php)
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) tool[c]=gcc ;; esac

# A JA4 line, not whatever a build tool printed last.
ja4_of() { grep -E "^[tqd][0-9]{2}[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$" | tail -n 1; }

reference=$(run_go 2>&1 | ja4_of)
echo "go (reference)  $reference"
fail=0
for lang in c python dotnet node java rust php; do
  if ! have "${tool[$lang]}"; then
    if [ "$strict" = 1 ]; then echo "$lang  MISSING ${tool[$lang]}"; fail=1; else echo "$lang  skipped (no ${tool[$lang]})"; fi
    continue
  fi
  out=$("run_$lang" 2>&1)
  got=$(printf '%s\n' "$out" | ja4_of)
  [ -n "$got" ] || got="no JA4 in the output; it ended with: $(printf '%s\n' "$out" | tail -n 3 | tr '\n' ' ')"
  if [ "$got" = "$reference" ]; then
    printf '%-15s %s\n' "$lang" "$got"
  else
    printf '%-15s DIFFERS: %s\n' "$lang" "$got"
    fail=1
  fi
done
exit $fail
