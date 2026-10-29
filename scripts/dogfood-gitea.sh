#!/usr/bin/env bash
# A local Gitea to dogfood keyless against: a real site with API tokens, SSH keys, OAuth apps and
# webhooks, on localhost only. Creates user "owner" with a random password that goes straight into
# the macOS Keychain (service "keyless", account "gitea") and is never printed.
set -euo pipefail
PORT="${PORT:-3300}"
NAME=keyless-gitea
IMAGE=gitea/gitea:1.22.6
CONFIG="${KEYLESS_CONFIG:-$HOME/.config/keyless/dogfood.json}"

docker info >/dev/null 2>&1 || { echo "Docker isn't running. Start OrbStack (orb start) or Docker Desktop and rerun." >&2; exit 1; }
if ! docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  docker run -d --name "$NAME" -p "127.0.0.1:$PORT:3000" \
    -e GITEA__security__INSTALL_LOCK=true \
    -e GITEA__server__ROOT_URL="http://localhost:$PORT/" \
    -e GITEA__service__DISABLE_REGISTRATION=true \
    -e GITEA__picture__DISABLE_GRAVATAR=true \
    -e GITEA__database__DB_TYPE=sqlite3 \
    "$IMAGE" >/dev/null
fi
docker start "$NAME" >/dev/null
printf 'Waiting for Gitea'
until curl -fsS "http://localhost:$PORT/api/healthz" >/dev/null 2>&1; do printf .; sleep 1; done
echo

PW="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-24)"
if docker exec -u git "$NAME" gitea admin user list | awk '{print $2}' | grep -qx owner; then
  docker exec -u git "$NAME" gitea admin user change-password --username owner --password "$PW" --must-change-password=false >/dev/null
else
  docker exec -u git "$NAME" gitea admin user create --username owner --email owner@example.test \
    --password "$PW" --must-change-password=false >/dev/null
fi
security add-generic-password -U -s keyless -a gitea -w "$PW"

mkdir -p "$(dirname "$CONFIG")"
python3 -I - "$CONFIG" "$PORT" <<'PY'
import json, os, sys
path, port = sys.argv[1], sys.argv[2]
cfg = json.load(open(path)) if os.path.exists(path) else {}
cfg.setdefault("chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
cfg.setdefault("credentials", {})["gitea"] = {
    "login_url": f"http://localhost:{port}/user/login",
    "post_login_url": f"http://localhost:{port}/",
    "username": "owner",
    "username_selector": "input[name=user_name]",
    "success": {"path": "/"},
    "writes": True,
}
json.dump(cfg, open(path, "w"), indent=2)
PY
echo "Gitea is up at http://localhost:$PORT (user: owner, password in Keychain)."
echo "Config: $CONFIG"
