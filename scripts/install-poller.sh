#!/bin/sh
# install-poller.sh: add, replace or remove the crontab entry that runs poll-inbox.sh.
#
# Usage: install-poller.sh [--every-minutes N] [--env-file PATH] [--cursor-file PATH] [--log PATH]
#                          [--exec COMMAND] [--print] [--uninstall]
#
#   --every-minutes N  Run every N minutes, 1-59 (default 1)
#   --env-file PATH    File that sets AGG_URL and AGG_TOKEN, mode 0600
#                      (default ${XDG_CONFIG_HOME:-$HOME/.config}/agent-aggregator/poller.env)
#   --cursor-file PATH Cursor file passed to poll-inbox.sh (default: poll-inbox.sh's default)
#   --log PATH         Output log (default <config dir>/poll-inbox.log)
#   --exec COMMAND     Exported to the job as AGG_POLL_EXEC: receives each page of new events on stdin
#   --print            Print the entry and change nothing
#   --uninstall        Remove the entry
#
# The entry ends with the marker "# agent-aggregator-poll-inbox". Re-running replaces that one line
# and keeps every other crontab line, so the script is idempotent.
# AGG_CRONTAB overrides the crontab command (used by the tests).
#
# Exit codes: 0 ok · 1 error (crontab unavailable, env file missing or readable by others) · 2 usage.

set -u
MARKER="# agent-aggregator-poll-inbox"
CRONTAB="${AGG_CRONTAB:-crontab}"
CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME:-.}/.config}/agent-aggregator"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)" || exit 1
POLLER="$SCRIPT_DIR/poll-inbox.sh"

EVERY=1
ENV_FILE="$CONFIG_DIR/poller.env"
CURSOR_FILE=""
LOG="$CONFIG_DIR/poll-inbox.log"
EXEC=""
MODE=install

usage() {
  printf 'install-poller: %s\nRun with --help for usage.\n' "$1" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --every-minutes) [ $# -ge 2 ] || usage "--every-minutes needs a value"; EVERY="$2"; shift 2 ;;
    --env-file) [ $# -ge 2 ] || usage "--env-file needs a value"; ENV_FILE="$2"; shift 2 ;;
    --cursor-file) [ $# -ge 2 ] || usage "--cursor-file needs a value"; CURSOR_FILE="$2"; shift 2 ;;
    --log) [ $# -ge 2 ] || usage "--log needs a value"; LOG="$2"; shift 2 ;;
    --exec) [ $# -ge 2 ] || usage "--exec needs a value"; EXEC="$2"; shift 2 ;;
    --print) MODE=print; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    -h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) usage "unknown option: $1" ;;
  esac
done

case "$EVERY" in
  '' | *[!0-9]*) usage "--every-minutes must be an integer between 1 and 59" ;;
esac
if [ "$EVERY" -lt 1 ] || [ "$EVERY" -gt 59 ]; then usage "--every-minutes must be an integer between 1 and 59"; fi
for value in "$ENV_FILE" "$CURSOR_FILE" "$LOG" "$EXEC"; do
  case "$value" in
    *%* | *"
"*) usage "paths and --exec must not contain '%' or newlines (cron treats % as a newline)" ;;
  esac
done

# Single-quote for sh: ' becomes '\''
quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

if [ "$EVERY" -eq 1 ]; then SCHEDULE="* * * * *"; else SCHEDULE="*/$EVERY * * * *"; fi
LINE="$SCHEDULE AGG_ENV_FILE=$(quote "$ENV_FILE")"
[ -n "$EXEC" ] && LINE="$LINE AGG_POLL_EXEC=$(quote "$EXEC")"
LINE="$LINE $(quote "$POLLER")"
[ -n "$CURSOR_FILE" ] && LINE="$LINE $(quote "$CURSOR_FILE")"
LINE="$LINE >> $(quote "$LOG") 2>&1 $MARKER"

if [ "$MODE" = print ]; then
  printf '%s\n' "$LINE"
  exit 0
fi

if [ "$MODE" = install ]; then
  [ -f "$ENV_FILE" ] || { printf 'install-poller: %s does not exist; create it with AGG_URL=... and AGG_TOKEN=... (mode 0600)\n' "$ENV_FILE" >&2; exit 1; }
  if [ -n "$(find "$ENV_FILE" -prune \( -perm -040 -o -perm -004 \) 2>/dev/null)" ]; then
    printf 'install-poller: %s is readable by other users; run: chmod 600 %s\n' "$ENV_FILE" "$(quote "$ENV_FILE")" >&2
    exit 1
  fi
  [ -x "$POLLER" ] || { printf 'install-poller: %s is not executable\n' "$POLLER" >&2; exit 1; }
  mkdir -p "$(dirname "$LOG")" || exit 1
fi

command -v "$CRONTAB" >/dev/null 2>&1 || {
  printf 'install-poller: %s is not available. Add this line with your scheduler instead:\n%s\n' "$CRONTAB" "$LINE" >&2
  exit 1
}

CURRENT="$("$CRONTAB" -l 2>/dev/null || true)"
KEPT="$(printf '%s\n' "$CURRENT" | grep -v -F "$MARKER" | sed '/^[[:space:]]*$/d')"
if [ "$MODE" = install ]; then
  NEXT="$(printf '%s\n%s\n' "$KEPT" "$LINE" | sed '/^[[:space:]]*$/d')"
else
  NEXT="$KEPT"
fi
printf '%s\n' "$NEXT" | "$CRONTAB" - || { printf 'install-poller: writing the crontab failed\n' >&2; exit 1; }

if [ "$MODE" = install ]; then
  printf '{"ok":true,"installed":true,"entry":"%s"}\n' "$(printf '%s' "$LINE" | sed 's/\\/\\\\/g; s/"/\\"/g')"
else
  printf '{"ok":true,"installed":false}\n'
fi
