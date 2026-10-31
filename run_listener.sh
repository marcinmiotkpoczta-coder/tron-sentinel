#!/usr/bin/env bash
# Start / stop / inspect the Telegram honeypot listener as a systemd --user service.
#   ./run_listener.sh start     # needs TG_API_ID + TG_API_HASH in .env, and listener.session
#   ./run_listener.sh status|logs|stop
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$(pwd)
UNIT_DIR="$HOME/.config/systemd/user"
UNIT=honeypot-listener
PY="$ROOT/venv/bin/python"

login_if_needed() {
  if [ ! -f "$ROOT/listener.session" ]; then
    echo ">> no listener.session: interactive login (phone + SMS code), once"
    "$PY" - <<'PY'
import asyncio, listener
cfg = listener.ListenerConfig.from_env()
client = listener._build_client(cfg)
async def go():
    await client.start()
    print("logged in as", (await client.get_me()).id)
    await client.disconnect()
asyncio.run(go())
PY
  fi
}

case "${1:-status}" in
  start)
    login_if_needed
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/$UNIT.service" <<EOF
[Unit]
Description=TRON honeypot Telegram listener
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
EnvironmentFile=$ROOT/.env
ExecStart=$PY $ROOT/listener.py
Restart=always
RestartSec=10
StandardOutput=append:$ROOT/listener.log
StandardError=append:$ROOT/listener.log

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "$UNIT.service"
    systemctl --user --no-pager status "$UNIT.service" | head -20
    echo ">> logs: tail -f $ROOT/listener.log"
    ;;
  stop)   systemctl --user disable --now "$UNIT.service" ;;
  status) systemctl --user --no-pager status "$UNIT.service" | head -20 ;;
  logs)   tail -n 100 -f "$ROOT/listener.log" ;;
  *)      echo "usage: $0 {start|stop|status|logs}" >&2; exit 2 ;;
esac
