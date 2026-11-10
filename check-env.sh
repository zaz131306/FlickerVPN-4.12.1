#!/usr/bin/env bash
# Диагностика среды для сборки flicker-box.aar + APK. Запускать НА СВОЕЙ машине:
#   bash check-env.sh
# Ничего не ставит и не качает — только смотрит и советует.
set -uo pipefail
ok(){ printf "  \033[32m✓\033[0m %s\n" "$*"; }
no(){ printf "  \033[31m✗\033[0m %s\n" "$*"; }
wr(){ printf "  \033[33m!\033[0m %s\n" "$*"; }
hr(){ printf "\n\033[1m── %s\033[0m\n" "$*"; }

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
[ -d "$SDK" ] || SDK="$HOME/Library/Android/sdk"

hr "1. JDK (нужен 17)"
if command -v java >/dev/null; then
  V=$(java -version 2>&1 | head -1)
  case "$V" in *'"17'*) ok "java: $V";; *) wr "java: $V — нужен именно 17 (Temurin/OpenJDK)";; esac
  command -v javac >/dev/null && ok "javac есть (JDK, не только JRE)" || no "javac нет — стоит JRE, нужен JDK"
else no "java не найдена"; fi
[ -n "${JAVA_HOME:-}" ] && ok "JAVA_HOME=$JAVA_HOME" || wr "JAVA_HOME не задан (скрипт сборки его ищет)"

hr "2. Go (нужен 1.26+)"
if command -v go >/dev/null; then
  ok "$(go version)"
  MC=$(go env GOMODCACHE); GV=$(go env GOPROXY)
  ok "GOMODCACHE=$MC"
  ok "GOPROXY=$GV"
  if [ -d "$MC" ]; then
    SZ=$(du -sh "$MC" 2>/dev/null | cut -f1)
    N=$(find "$MC" -maxdepth 3 -type d 2>/dev/null | wc -l)
    ok "кэш модулей: $SZ, ~$N пакетов"
    if [ -d "$MC/github.com/sagernet" ]; then
      ok "есть github.com/sagernet/* — дерево sing-box уже скачано (это ~2.6 ГБ, заново не нужно)"
      ls -d "$MC"/github.com/sagernet/sing-box* 2>/dev/null | sed 's|.*/|      |' | head -3
    else
      wr "github.com/sagernet/* НЕ найден — дерево sing-box придётся качать"
      wr "  → см. пункт 4 про зеркала"
    fi
    [ -d "$MC/github.com/sagernet/gomobile@v0.1.12" ] && ok "gomobile v0.1.12 в кэше" || wr "gomobile v0.1.12 не в кэше (поставится командой go install)"
  else
    wr "каталог кэша пуст — все модули придётся качать"
  fi
else no "go не найден — нужен Go 1.26+ (go.dev/dl или mirror)" ; fi

hr "3. Android SDK / NDK"
if [ -d "$SDK" ]; then
  ok "SDK: $SDK"
  [ -d "$SDK/platforms/android-35" ] && ok "platforms;android-35" || no "platforms;android-35 — поставить в SDK Manager"
  ls -d "$SDK"/build-tools/3[4-9]* 2>/dev/null | head -1 | sed 's/^/  /' >/dev/null && ok "build-tools 34+: $(ls -1 "$SDK/build-tools" 2>/dev/null | tail -1)" || no "build-tools;34.0.0 — поставить"
  NDKDIR="$SDK/ndk/27.2.12479018"
  if [ -d "$NDKDIR" ]; then
    ok "NDK 27.2.12479018 найден"
  else
    no "NDK 27.2.12479018 НЕ найден (нужен именно он — см. ndkVersion в build.gradle.kts)"
    echo "      установлено:"; ls -1 "$SDK/ndk" 2>/dev/null | sed 's/^/        /' || echo "        (ничего)"
    echo "      SDK Manager → SDK Tools → NDK (Side by side) → Show Package Details → 27.2.12479018"
  fi
else no "Android SDK не найден (искали $SDK)"; fi

hr "4. Сеть: что доступно (тайминг, 15 c на точку)"
probe(){ # name url key
  python3 - "$1" "$2" "$3" <<'PYEOF'
import sys, time, urllib.request
name, url, key = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    t0 = time.time()
    method = "GET" if "go.dev" in url else "HEAD"
    r = urllib.request.urlopen(urllib.request.Request(url, method=method, headers={"User-Agent": "Mozilla/5.0"}), timeout=15)
    ms = int((time.time() - t0) * 1000)
    code = r.status
except Exception as e:
    ms = -1
    code = getattr(e, "code", None) or type(e).__name__
if code == 200:
    print("  \033[32m\u2713\033[0m %-34s %4d \u043c\u0441" % (name, ms))
    open("/tmp/.probe_" + key, "w").write(str(ms))
else:
    print("  \033[31m\u2717\033[0m %-34s %s" % (name, code))
PYEOF
}
if command -v python3 >/dev/null; then
  rm -f /tmp/.probe_*
  probe "proxy.golang.org"        "https://proxy.golang.org/github.com/sagernet/sing-box/@v/list"      go1
  probe "goproxy.cn (Китай)"      "https://goproxy.cn/github.com/sagernet/sing-box/@v/list"            go2
  probe "goproxy.io"              "https://goproxy.io/github.com/sagernet/sing-box/@v/list"            go3
  probe "mirrors.aliyun.com"      "https://mirrors.aliyun.com/goproxy/github.com/sagernet/sing-box/@v/list" go4
  probe "dl.google.com (AGP/SDK)" "https://dl.google.com/android/maven2/com/android/tools/build/gradle/8.7.3/gradle-8.7.3.pom" gg
  probe "services.gradle.org"     "https://services.gradle.org/distributions/gradle-8.9-bin.zip"       gd
  probe "repo1.maven.org"         "https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/1.9.24/kotlin-stdlib-1.9.24.pom" mc
  probe "go.dev/dl"               "https://go.dev/dl/?mode=json"                                       gv
  probe "github.com"              "https://github.com"                                                 gh
else
  wr "python3 не найден — пункт 4 пропущен"
fi

hr "5. Итог"
BEST=""
for k in go1 go2 go3 go4; do
  [ -f "/tmp/.probe_$k" ] || continue
  case $k in go1) n="https://proxy.golang.org,direct";; go2) n="https://goproxy.cn,direct";;
               go3) n="https://goproxy.io,direct";; go4) n="https://mirrors.aliyun.com/goproxy/,direct";; esac
  if [ -z "$BEST" ]; then BEST="$n"; BESTMS=$(cat /tmp/.probe_$k); else
    [ "$(cat /tmp/.probe_$k)" -lt "$BESTMS" ] && { BEST="$n"; BESTMS=$(cat /tmp/.probe_$k); }
  fi
done
if [ -n "$BEST" ]; then
  echo "  Быстрее всех зеркало Go-модулей: $BEST (${BESTMS} мс)"
  echo "  Применить:"
  echo "    go env -w GOPROXY='$BEST'"
else
  echo "  Ни одно зеркало Go-модулей не ответило — нужен прокси/VPN,"
  echo "  либо офлайн-набор pkg-mod (см. README-OFFLINE.md)."
fi
[ -f /tmp/.probe_gg ] && echo "  dl.google.com доступен → AGP/androidx скачаются сами" \
  || echo "  dl.google.com НЕ доступен → Gradle sync не пройдёт без прокси; нужен офлайн-набор"
[ -f /tmp/.probe_gd ] && echo "  services.gradle.org доступен → Gradle 8.9 скачается сам (или возьмите gradle-8.9-bin.zip из набора)" \
  || echo "  services.gradle.org НЕ доступен → используйте gradle-8.9-bin.zip из набора (см. README-OFFLINE.md)"
rm -f /tmp/.probe_*
