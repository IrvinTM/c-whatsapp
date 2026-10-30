#!/bin/sh
# Local live-test helper. Reads the ignored auth_info/test.env so a test
# phone number never has to live in git or on a command line.
#
# Usage:
#   tools/live-test.sh send [TEXT]
#   tools/live-test.sh listen [EXTRA ARGS]
#   tools/live-test.sh daemon [EXTRA ARGS]
set -eu

cd "$(dirname "$0")/.."

env_file="test.env"
[ -f "$env_file" ] || env_file="auth_info/test.env"
if [ ! -f "$env_file" ]; then
    echo "missing test.env (put CWA_TEST_TO=digits there)" >&2
    exit 2
fi

set -a
. "./$env_file"
set +a

: "${CWA_TEST_TO:?set CWA_TEST_TO in $env_file}"
# Chat commands are only accepted from CWA_ALLOW (default: the test number).
CWA_ALLOW="${CWA_ALLOW:-$CWA_TEST_TO}"
export CWA_ALLOW

cmd="${1:-send}"
shift || true

case "$cmd" in
send)
    text="${*:-ping from c-whatsapp}"
    exec ./build/c-whatsapp --auth-dir auth_info \
        --to "$CWA_TEST_TO" --text "$text"
    ;;
listen)
    exec ./build/c-whatsapp --auth-dir auth_info --listen \
        --read-receipts --timeout 0 "$@"
    ;;
daemon)
    bin=./build/tiny/c-whatsapp
    [ -x "$bin" ] || bin=./build/c-whatsapp
    exec "$bin" --auth-dir auth_info --daemon --read-receipts --timeout 0 "$@"
    ;;
*)
    echo "usage: tools/live-test.sh {send [TEXT]|listen|daemon} [ARGS...]" >&2
    exit 2
    ;;
esac
