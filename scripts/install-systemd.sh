#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${SERVICE_NAME:-bluetodo}"
SERVICE_USER="${SERVICE_USER:-bluetodo}"
SERVICE_GROUP="${SERVICE_GROUP:-bluetodo}"
PREFIX="${PREFIX:-/usr/local}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bluetodo}"
STATE_DIR="${STATE_DIR:-/var/lib/bluetodo}"
MASTER_KEY_FILE="${MASTER_KEY_FILE:-$CONFIG_DIR/master.key}"
BIN_PATH="$PREFIX/bin/bluetodo"
UNIT_SOURCE="$ROOT_DIR/packaging/systemd/bluetodo.service"
ENV_SOURCE="$ROOT_DIR/packaging/systemd/bluetodo.env.example"
UNIT_TARGET="$SYSTEMD_DIR/$SERVICE_NAME.service"
ENV_TARGET="$CONFIG_DIR/bluetodo.env"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found" >&2
    exit 1
fi

NOLOGIN_SHELL="/usr/sbin/nologin"
if [[ ! -x "$NOLOGIN_SHELL" ]]; then
    NOLOGIN_SHELL="/usr/bin/false"
fi

if ! getent group "$SERVICE_GROUP" >/dev/null; then
    groupadd --system "$SERVICE_GROUP"
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd \
        --system \
        --gid "$SERVICE_GROUP" \
        --home-dir "$STATE_DIR" \
        --create-home \
        --shell "$NOLOGIN_SHELL" \
        "$SERVICE_USER"
fi

install -d -m 0755 "$PREFIX/bin"
install -d -m 0755 "$SYSTEMD_DIR"
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$(dirname "$MASTER_KEY_FILE")"

echo "building release binary"
cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"

install -m 0755 "$ROOT_DIR/target/release/bluetodo" "$BIN_PATH"
install -m 0644 "$UNIT_SOURCE" "$UNIT_TARGET"

if [[ ! -f "$ENV_TARGET" ]]; then
    install -m 0640 -o root -g "$SERVICE_GROUP" "$ENV_SOURCE" "$ENV_TARGET"
fi

if [[ ! -f "$MASTER_KEY_FILE" ]]; then
    umask 0077
    head -c 32 /dev/urandom | base64 >"$MASTER_KEY_FILE"
    chown root:"$SERVICE_GROUP" "$MASTER_KEY_FILE"
    chmod 0640 "$MASTER_KEY_FILE"
fi

systemctl daemon-reload

cat <<EOF
Installed:
  binary: $BIN_PATH
  unit:   $UNIT_TARGET
  env:    $ENV_TARGET
  key:    $MASTER_KEY_FILE

Next steps:
  1. Edit $ENV_TARGET if you need custom paths or client update artifacts.
  2. Run: systemctl enable --now $SERVICE_NAME.service
  3. Check: systemctl status $SERVICE_NAME.service
EOF
