#!/usr/bin/env bash
# Install llm-honeypot as a systemd service. Run as root from the repository root:
#   sudo ./deploy/install.sh
set -euo pipefail

PREFIX=/opt/llm-honeypot
CONF_DIR=/etc/llm-honeypot
ENV_FILE=$CONF_DIR/honeypot.env
SERVICE_USER=llm-honeypot
UNIT=/etc/systemd/system/llm-honeypot.service
SRC="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -m 0755 "$PREFIX"
rm -rf "$PREFIX/src"
install -d -m 0755 "$PREFIX/src"
cp -r "$SRC/honeypot" "$SRC/pyproject.toml" "$SRC/README.md" "$PREFIX/src/"
find "$PREFIX/src" -name '__pycache__' -prune -exec rm -rf {} +

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    echo "Python 3.11 or newer is required (found $(python3 --version 2>&1))" >&2
    exit 1
fi

# A venv without pip is left behind when an earlier run failed half way; rebuild it.
if [[ ! -x $PREFIX/venv/bin/pip ]]; then
    rm -rf "$PREFIX/venv"
    if ! python3 -m venv "$PREFIX/venv"; then
        rm -rf "$PREFIX/venv"
        echo "creating the venv failed - install the venv module: apt install python3-venv" >&2
        exit 1
    fi
fi
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet "$PREFIX/src"

install -d -m 0750 -o root -g "$SERVICE_USER" "$CONF_DIR"
if [[ ! -f $ENV_FILE ]]; then
    install -m 0640 -o root -g "$SERVICE_USER" "$SRC/.env.example" "$ENV_FILE"
    sed -i -e '/^DATA_DIR=/d' -e '/^LOG_DIR=/d' "$ENV_FILE"
    echo "created $ENV_FILE - fill in LLM_PROVIDER, LLM_API_KEY and ROOT_PASSWORD"
fi

install -m 0644 "$SRC/deploy/llm-honeypot.service" "$UNIT"
systemctl daemon-reload

cat <<EOF

Installed. Next steps:
  1. Edit $ENV_FILE
  2. systemctl enable --now llm-honeypot
  3. journalctl -u llm-honeypot -f        (service log)
     ls /var/log/llm-honeypot/            (session recordings)
EOF
