#!/usr/bin/env bash
# Installs the Teeckbox agent on Linux (systemd) with one command, as root:
#
#   curl -fsSL https://github.com/Teeckbox/teeckbox-agent/releases/latest/download/teeckbox-agent-install.sh \
#     | sudo bash -s -- --url https://teeckbox.example.com --code tbe_... --allow erp.corp.example.com:443
#
# It downloads the release this script belongs to, checks its SHA-256, installs the binary, creates the account that runs it,
# enrols the agent with the one-time code (Connections > Agents in Teeckbox), writes the allow list and starts the service.
# Run it again without --code to upgrade; the keys and the configuration are kept.
set -euo pipefail

VERSION="@VERSION@"      # stamped by the release workflow; --version gives one when this file is run from the repository
BASE_URL=""              # where the files of the release are; default: the GitHub release (--download-url for a mirror)
USER_NAME="teeckbox-agent"
BINARY="/usr/local/bin/teeckbox-agent"
CONFIG_DIR="/etc/teeckbox-agent"
CONFIG="$CONFIG_DIR/agent.yaml"
STATE_DIR="/var/lib/teeckbox-agent"
UNIT="/etc/systemd/system/teeckbox-agent.service"

url=""; code=""; allow=""; label=""; proxy=""; force=0; uninstall=0; purge=0

usage() {
  cat <<'EOF'
Install, upgrade or remove the Teeckbox agent (Linux, systemd). Run as root.

  --url <address>        the address of Teeckbox (https://...)                          first install
  --code <code>          the one-time enrollment code (tbe_...)                          first install
  --allow <list>         what the agent may call: host names (erp.example.com, *.example.com) or addresses or
                         ranges (10.20.0.0/16), optionally followed by :port, separated by commas
  --label <text>         how this instance is shown to the administrator (default: the machine name)
  --proxy <url>          an HTTP proxy to reach Teeckbox
  --force                enrol again an agent that already is, replacing its keys
  --version <x.y.z>      the version to install (default: the one of this script)
  --download-url <url>   where to download the release files from, for a mirror
  --uninstall            stop and remove the agent (--purge also removes its keys and configuration)
EOF
}

die() { echo "teeckbox-agent: $*" >&2; exit 1; }
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url) url="${2:?--url needs a value}"; shift 2 ;;
    --code) code="${2:?--code needs a value}"; shift 2 ;;
    --allow) allow="${2:?--allow needs a value}"; shift 2 ;;
    --label) label="${2:?--label needs a value}"; shift 2 ;;
    --proxy) proxy="${2:?--proxy needs a value}"; shift 2 ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --download-url) BASE_URL="${2:?--download-url needs a value}"; shift 2 ;;
    --force) force=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    --purge) purge=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option '$1'" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run this as root (sudo)."
command -v systemctl >/dev/null 2>&1 || die "systemd was not found. Use the container image or the manual installation of the README."

if [ "$uninstall" -eq 1 ]; then
  say "Removing the Teeckbox agent"
  systemctl disable --now teeckbox-agent 2>/dev/null || true
  rm -f "$UNIT" "$BINARY"
  systemctl daemon-reload
  if [ "$purge" -eq 1 ]; then
    rm -rf "$CONFIG_DIR" "$STATE_DIR"
    id "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" 2>/dev/null || true
    say "Removed, with its keys and configuration. Disable the instance in Teeckbox (Connections > Agents) too."
  else
    say "Removed. The keys ($STATE_DIR) and the configuration ($CONFIG_DIR) are kept; add --purge to delete them."
  fi
  exit 0
fi

case "$VERSION" in
  @*) die "this file does not know which version to install: give --version <x.y.z>, or use the script of a release." ;;
esac

case "$(uname -m)" in
  x86_64|amd64) rid="linux-x64" ;;
  aarch64|arm64) rid="linux-arm64" ;;
  *) die "the architecture $(uname -m) is not supported (x86-64 and arm64 are)." ;;
esac

fetch() {  # fetch <url> <file>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "curl or wget is needed to download the agent."
  fi
}

as_agent() {  # as_agent <command...>: runs as the account of the service, so that the keys belong to it
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$USER_NAME" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$USER_NAME" -- "$@"
  else
    die "runuser or sudo is needed to enrol the agent as its own account."
  fi
}

enrolled=0
[ -f "$STATE_DIR/state.json" ] && enrolled=1

if [ "$enrolled" -eq 1 ] && [ "$force" -eq 0 ]; then
  [ -z "$code" ] || die "this agent is already enrolled. Add --force to enrol it again (its keys are replaced), or leave --code out to upgrade it."
  enroll_now=0
else
  [ -n "$url" ] && [ -n "$code" ] || die "a first installation needs --url (the address of Teeckbox) and --code (Connections > Agents > New agent in Teeckbox)."
  enroll_now=1
fi

work="$(mktemp -d)"
cfgwork="$(mktemp -d)"
trap 'rm -rf "$work" "$cfgwork"' EXIT

[ -n "$BASE_URL" ] || BASE_URL="https://github.com/Teeckbox/teeckbox-agent/releases/download/v$VERSION"
archive="teeckbox-agent-$VERSION-$rid.tar.gz"

say "Downloading the agent $VERSION ($rid)"
fetch "$BASE_URL/$archive" "$work/$archive" || die "$BASE_URL/$archive could not be downloaded."
fetch "$BASE_URL/SHA256SUMS.txt" "$work/SHA256SUMS.txt" || die "$BASE_URL/SHA256SUMS.txt could not be downloaded."
( cd "$work" && grep -E "[ *]${archive//./\.}\$" SHA256SUMS.txt | sha256sum --check --status ) || die "the SHA-256 of $archive is not the published one: the download is corrupt, nothing was installed."
tar -xzf "$work/$archive" -C "$work"
dist="$work/teeckbox-agent-$VERSION-$rid"
[ -x "$dist/teeckbox-agent" ] || die "the archive does not hold teeckbox-agent."

say "Installing the program"
systemctl stop teeckbox-agent 2>/dev/null || true
install -m 0755 "$dist/teeckbox-agent" "$BINARY"

id "$USER_NAME" >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --shell "$(command -v nologin || echo /usr/sbin/nologin)" "$USER_NAME"
install -d -o root -g "$USER_NAME" -m 0750 "$CONFIG_DIR"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$STATE_DIR"

if [ "$enroll_now" -eq 1 ]; then
  say "Enrolling the agent with Teeckbox"
  # The agent writes its first agent.yaml where its own account can write, then it is installed where the account can only read.
  chown "$USER_NAME:$USER_NAME" "$cfgwork"; chmod 0700 "$cfgwork"
  args=(enroll --url "$url" --code "$code" --config "$cfgwork/agent.yaml")
  [ "$force" -eq 1 ] && args+=(--force)
  [ -n "$label" ] && args+=(--label "$label")
  [ -n "$proxy" ] && args+=(--proxy "$proxy")
  [ -n "$allow" ] && args+=(--allow "$allow")
  as_agent env TEECKBOX_AGENT_DATA_FOLDER="$STATE_DIR" "$BINARY" "${args[@]}" || die "the enrollment failed (see above); nothing is running. The code is single-use: get a new one in Teeckbox."
  if [ ! -f "$CONFIG" ] || [ -n "$allow" ] || [ -n "$proxy" ]; then
    install -o root -g "$USER_NAME" -m 0640 "$cfgwork/agent.yaml" "$CONFIG"
  fi
elif [ -n "$allow" ] || [ -n "$proxy" ]; then
  say "Note: --allow and --proxy only apply to a first enrollment. Edit $CONFIG instead."
fi

say "Starting the service"
install -m 0644 "$dist/teeckbox-agent.service" "$UNIT"
systemctl daemon-reload
systemctl enable teeckbox-agent >/dev/null 2>&1
systemctl restart teeckbox-agent
sleep 2
systemctl is-active --quiet teeckbox-agent || { journalctl -u teeckbox-agent -n 20 --no-pager 2>/dev/null || true; die "the service did not start: see 'journalctl -u teeckbox-agent'."; }

say "The Teeckbox agent $VERSION is running."
echo "    Logs:           journalctl -u teeckbox-agent -f"
echo "    Configuration:  $CONFIG  (the allow list; restart is not needed, it is read again when it changes)"
grep -q '^allow: \[\]' "$CONFIG" 2>/dev/null && echo "    Warning: the allow list is empty, so every call is refused: list the destinations in $CONFIG."
exit 0
