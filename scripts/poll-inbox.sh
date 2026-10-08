#!/bin/sh
# poll-inbox.sh: read new inbox events with POSIX sh + curl (no Node.js, no jq).
#
# Usage: poll-inbox.sh [CURSOR_FILE]
#
# Environment:
#   AGG_URL         Agent API base, e.g. https://aggregator.example.com/api (requests go to $AGG_URL/v1/inbox)
#   AGG_TOKEN       Agent credential
#   AGG_ENV_FILE    Optional file that sets AGG_URL and AGG_TOKEN (mode 0600); it is sourced with '.'
#   AGG_POLL_EXEC   Optional command. Each page with new events is piped to it on stdin as one JSON
#                   line; the cursor advances only if the command exits 0.
#   AGG_POLL_LIMIT  Events per page, 1-100 (default 50)
#
# Without AGG_POLL_EXEC, each page with new events is printed to stdout as one JSON line:
#   {"events":[...],"cursor":"c1....","has_more":false}
# The cursor file defaults to ${XDG_CONFIG_HOME:-$HOME/.config}/agent-aggregator/inbox-sh.cursor.
# The credential is passed to curl on stdin (curl -K -), never on the command line.
#
# Exit codes: 0 new events · 3 nothing new (or another run holds the lock) · 4 credential missing or
# rejected · 1 any other error (network, HTTP error, hook failure, corrupt cursor file).

set -u
umask 077

fail() {
  printf 'poll-inbox: %s\n' "$1" >&2
  exit "${2:-1}"
}

if [ -n "${AGG_ENV_FILE:-}" ]; then
  [ -r "$AGG_ENV_FILE" ] || fail "cannot read AGG_ENV_FILE ($AGG_ENV_FILE)"
  # shellcheck disable=SC1090
  . "$AGG_ENV_FILE"
fi

[ -n "${AGG_URL:-}" ] || fail "set AGG_URL to the agent API base, e.g. https://aggregator.example.com/api"
[ -n "${AGG_TOKEN:-}" ] || fail "set AGG_TOKEN (or AGG_ENV_FILE)" 4
case "$AGG_TOKEN" in
  *[!A-Za-z0-9_-]*) fail "AGG_TOKEN contains unexpected characters" 4 ;;
esac
command -v curl >/dev/null 2>&1 || fail "curl is required"

LIMIT="${AGG_POLL_LIMIT:-50}"
case "$LIMIT" in
  '' | *[!0-9]*) fail "AGG_POLL_LIMIT must be an integer between 1 and 100" ;;
esac
if [ "$LIMIT" -lt 1 ] || [ "$LIMIT" -gt 100 ]; then fail "AGG_POLL_LIMIT must be an integer between 1 and 100"; fi

CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME:-.}/.config}/agent-aggregator"
CURSOR_FILE="${1:-$CONFIG_DIR/inbox-sh.cursor}"
mkdir -p "$(dirname "$CURSOR_FILE")" || fail "cannot create $(dirname "$CURSOR_FILE")"

LOCK="$CURSOR_FILE.lock"
BODY="$CURSOR_FILE.body.$$"
# A lock left behind by a killed run is stale after 10 minutes.
if [ -d "$LOCK" ] && [ -n "$(find "$LOCK" -prune -mmin +10 2>/dev/null)" ]; then
  rmdir "$LOCK" 2>/dev/null
fi
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'poll-inbox: another run holds %s; skipping\n' "$LOCK" >&2
  exit 3
fi
trap 'rm -f "$BODY"; rmdir "$LOCK" 2>/dev/null' EXIT
trap 'exit 1' INT TERM HUP

CURSOR=""
if [ -f "$CURSOR_FILE" ]; then
  CURSOR="$(cat "$CURSOR_FILE")"
fi
CORRUPT="cursor file $CURSOR_FILE is corrupt; delete it to read from the beginning"
case "$CURSOR" in
  '') ;;
  c1.?*) case "${CURSOR#c1.}" in *[!A-Za-z0-9_-]*) fail "$CORRUPT" ;; esac ;;
  *) fail "$CORRUPT" ;;
esac

PAGES=0
WITH_EVENTS=0
while [ "$PAGES" -lt 20 ]; do
  PAGES=$((PAGES + 1))
  QUERY="limit=$LIMIT"
  [ -n "$CURSOR" ] && QUERY="$QUERY&cursor=$CURSOR"
  STATUS="$(printf 'header = "Authorization: Bearer %s"\n' "$AGG_TOKEN" |
    curl -sS -K - -o "$BODY" -w '%{http_code}' --max-time 30 \
      -A 'agent-aggregator-poller/0.1' -H 'Accept: application/json' \
      "$AGG_URL/v1/inbox?$QUERY")" || fail "request to $AGG_URL failed"
  case "$STATUS" in
    200) ;;
    401) fail "credential missing or rejected (HTTP 401)" 4 ;;
    *) fail "HTTP $STATUS from the inbox: $(head -c 300 "$BODY")" ;;
  esac
  PAGE="$(cat "$BODY")"
  # The page-level cursor is the only "cursor" immediately followed by "has_more".
  NEXT="$(printf '%s' "$PAGE" | sed -n 's/.*"cursor":"\(c1\.[A-Za-z0-9_-]*\)","has_more":[a-z]*}$/\1/p')"
  [ -n "$NEXT" ] || fail "unexpected inbox response"
  case "$PAGE" in
    *'"has_more":true}') MORE=1 ;;
    *) MORE=0 ;;
  esac
  case "$PAGE" in
    '{"events":[]'*) ;;
    *)
      if [ -n "${AGG_POLL_EXEC:-}" ]; then
        printf '%s\n' "$PAGE" | sh -c "$AGG_POLL_EXEC"
        RC=$?
        [ "$RC" -eq 0 ] || fail "hook exited $RC; cursor not advanced"
      else
        printf '%s\n' "$PAGE"
      fi
      WITH_EVENTS=$((WITH_EVENTS + 1))
      ;;
  esac
  if [ "$NEXT" != "$CURSOR" ]; then
    if ! { printf '%s' "$NEXT" > "$CURSOR_FILE.tmp.$$" && mv -f "$CURSOR_FILE.tmp.$$" "$CURSOR_FILE"; }; then
      fail "cannot write $CURSOR_FILE"
    fi
    CURSOR="$NEXT"
  fi
  [ "$MORE" -eq 1 ] || break
done

[ "$WITH_EVENTS" -gt 0 ] && exit 0
exit 3
