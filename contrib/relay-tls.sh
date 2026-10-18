#!/usr/bin/env bash
# Put TLS in front of the relay, on the relay host.
#
#   contrib/relay-tls.sh relay.example.com
#
# Run this ON the relay host, as root, once DNS for that name points at this
# machine. Caddy obtains and renews a certificate automatically; the relay
# itself stays exactly as it is and simply stops being reachable directly.
#
# Why a proxy rather than TLS in the relay: the relay is a hand-rolled HTTP
# server kept small enough to read, and adding certificate issuance, renewal
# and a TLS state machine to it would undo that. Caddy does one job here and
# the relay's own code does not change.
set -eu
NAME=${1:-}
[ -n "$NAME" ] || { echo "usage: $0 <hostname>" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root on the relay host" >&2; exit 2; }

# The name must already resolve HERE, or Caddy's certificate request fails in
# a way that rate-limits the account. Checked first, loudly.
ME=$(curl -s -m 10 https://api.ipify.org || true)
GOT=$(getent hosts "$NAME" | head -1 | awk '{print $1}' || true)
if [ -z "$GOT" ]; then
  echo "$NAME does not resolve yet. Add an A record pointing at ${ME:-this host} and wait." >&2
  exit 1
fi
if [ -n "$ME" ] && [ "$GOT" != "$ME" ]; then
  echo "$NAME resolves to $GOT, but this host is $ME." >&2
  echo "Fix the A record before running this: a failed certificate request counts" >&2
  echo "against a rate limit that takes hours to clear." >&2
  exit 1
fi

if ! command -v caddy >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy
fi

cat > /etc/caddy/Caddyfile <<EOF
# Terminates TLS and passes the request to the relay on loopback.
$NAME {
	reverse_proxy 127.0.0.1:7788
	# The relay already bounds bodies; this stops a body that large from
	# being buffered by the proxy on a small host.
	request_body {
		max_size 40MB
	}
}
EOF

# The relay moves to loopback: with a proxy in front, listening on 0.0.0.0
# would leave the plaintext port open beside the TLS one, and a client that
# used it would get no verification while believing it had.
sed -i 's|--bind 0.0.0.0:7788|--bind 127.0.0.1:7788|' /etc/systemd/system/ctx-relay.service
systemctl daemon-reload
systemctl restart ctx-relay

ufw allow 80/tcp  comment 'caddy http-01 challenge' >/dev/null 2>&1 || true
ufw allow 443/tcp comment 'gage relay over TLS' >/dev/null 2>&1 || true
# The plaintext port is closed, not merely bypassed.
ufw delete allow 7788/tcp >/dev/null 2>&1 || true

systemctl enable --now caddy
systemctl restart caddy
sleep 5

echo
echo "checking from the outside:"
curl -sS -m 20 "https://$NAME/health" && echo
echo
echo "Now tell people:  gage connect https://$NAME"
echo "And on each machine that already uses the plaintext address:"
echo "  gage connect https://$NAME     # re-registers against the verified one"
