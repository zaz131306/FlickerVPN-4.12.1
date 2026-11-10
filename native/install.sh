#!/usr/bin/env bash
# install.sh — сборка и установка native host FLICKER VPN (Linux / macOS).
#
#   ./install.sh                # Firefox (по умолчанию)
#   ./install.sh --browser chrome
#   ./install.sh --prefix /usr/local/bin   # требует root для /usr/local/bin
#
# Скрипт:
#   1. собирает flicker-host из исходников (go build);
#   2. кладёт бинарник в PREFIX (по умолчанию ~/.local/bin, фолбэк /usr/local/bin);
#   3. регистрирует NM-манифест с РЕАЛЬНЫМ абсолютным путём до бинарника.
set -euo pipefail
cd "$(dirname "$0")"

BROWSER="firefox"
PREFIX=""
while [ $# -gt 0 ]; do
  case "$1" in
    --browser) BROWSER="$2"; shift 2 ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    *) echo "Неизвестный флаг: $1"; exit 1 ;;
  esac
done

command -v go >/dev/null 2>&1 || { echo "❌ Нужен Go (1.26+)"; exit 1; }

echo "📦 Сборка flicker-host..."
go build -tags "with_utls with_gvisor" -o flicker-host ./cmd/flicker-host

if [ -z "$PREFIX" ]; then
  if [ -w "/usr/local/bin" ]; then PREFIX="/usr/local/bin"; else PREFIX="$HOME/.local/bin"; fi
fi
mkdir -p "$PREFIX"
BIN="$PREFIX/flicker-host"
cp -f flicker-host "$BIN"
chmod +x "$BIN"
echo "📥 Бинарник: $BIN"

case "$BROWSER" in
  firefox) MANIFEST_DIR="$HOME/.mozilla/native-messaging-hosts" ;;
  chrome)  MANIFEST_DIR="$HOME/.config/google-chrome/NativeMessagingHosts" ;;
  chromium) MANIFEST_DIR="$HOME/.config/chromium/NativeMessagingHosts" ;;
  edge)    MANIFEST_DIR="$HOME/.config/microsoft-edge/NativeMessagingHosts" ;;
  *) echo "❌ Неизвестный браузер: $BROWSER"; exit 1 ;;
esac
mkdir -p "$MANIFEST_DIR"
MANIFEST="$MANIFEST_DIR/com.flicker.vpn.json"

# allowed_origins для Chromium-браузеров, allowed_extensions для Firefox
if [ "$BROWSER" = "firefox" ]; then
  ALLOW='"allowed_extensions": ["flicker-vpn@local.dev"]'
else
  ALLOW='"allowed_origins": ["chrome-extension://flickervpnlocaldev/"]'
fi

cat > "$MANIFEST" <<EOF
{
  "name": "com.flicker.vpn",
  "description": "FLICKER VPN native tunnel (VLESS Reality / Trojan / WireGuard / HY2)",
  "path": "$BIN",
  "type": "stdio",
  $ALLOW
}
EOF
echo "📝 NM-манифест: $MANIFEST"

echo
echo "✅ Установка завершена."
echo "Далее:"
echo "  1. Перезапустите браузер."
echo "  2. Firefox: about:debugging → This Firefox → Load Temporary Add-on → manifest.json"
echo "     (Chromium: chrome://extensions → Load unpacked)"
echo "  3. Проверка: curl -x socks5h://127.0.0.1:1080 https://ifconfig.me (после подключения)"

