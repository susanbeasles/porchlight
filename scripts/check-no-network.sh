#!/usr/bin/env bash
# SPEC C1: v0 makes zero outbound connections. Two checks:
#   1. No source file outside tests references a network API.
#   2. No crate in the dependency graph is a network crate.
set -uo pipefail
cd "$(dirname "$0")/.."
rc=0

pattern='URLSession|NWConnection|CFSocket|std::net::|tokio::net|reqwest|hyper::|ureq|curl_easy|libcurl|getaddrinfo|(^|[^A-Za-z0-9_])(connect|socket)\('
hits="$(grep -rnE "$pattern" --include='*.rs' --include='*.swift' --include='*.c' --include='*.h' --include='*.m' crates apple 2>/dev/null \
  | grep -vE '(^|/)tests/|_test\.rs:|/csrc/xpc_shim\.c:|^[^:]*:[0-9]+:\s*//' || true)"
if [[ -n "$hits" ]]; then
  echo "check-no-network: network API reference in source:"
  echo "$hits"
  rc=1
fi

deny='^(reqwest|hyper|hyper-util|h2|tokio|tokio-util|ureq|curl|curl-sys|native-tls|rustls|openssl|openssl-sys|mio|socket2|tungstenite|async-std|smol|isahc|attohttpc|minreq|trust-dns-resolver|hickory-resolver) '
# Fail closed: a cargo error or an empty graph means nothing was inspected.
if ! graph="$(cargo tree --workspace --all-features --edges normal --prefix none --locked)"; then
  echo "check-no-network: cargo tree failed; dependency graph not inspected"
  rc=1
  graph=""
elif [[ -z "$graph" ]]; then
  echo "check-no-network: cargo tree returned an empty graph"
  rc=1
fi
graph="$(echo "$graph" | sort -u)"
bad="$(echo "$graph" | grep -E "$deny" || true)"
if [[ -n "$bad" ]]; then
  echo "check-no-network: network crate in the dependency graph:"
  echo "$bad"
  rc=1
fi

[[ $rc -eq 0 ]] && echo "check-no-network: ok"
exit $rc
