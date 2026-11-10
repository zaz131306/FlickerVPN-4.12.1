#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# build-libbox-aar.sh — сборка android/app/libs/flicker-box.aar:
#   * sing-box v1.14.2 (experimental/libbox) — GPL-3.0;
#   * native/mobile — Go-фасад FLICKER VPN (подписки/пробы/конфиги).
# Одним AAR под arm64-v8a (устройства) + x86_64 (эмулятор Android Studio)
# (gomobile-форк sagernet, как у sing-box/SFA).
#
# Требования (машина разработчика, НЕ песочница):
#   - Linux/macOS (или Windows через WSL2);
#   - Go 1.26+ (go.mod ядра);
#   - JDK 17 (openjdk/temurin 17 — требование тулчейна sing-box и AGP 8.7);
#   - Android NDK 27.2.12479018 — ТОЧНО эта версия: она же зашита в
#     android/app/build.gradle.kts (ndkVersion) и в .github/workflows/android.yml.
#     Дефолт AGP 8.7 — 27.0.12077973, он НЕ подойдёт без правки ndkVersion;
#   - ~8 ГБ свободного места (две ABI вместо одной), ~8 ГБ RAM на сборку.
#
# Использование:
#   ./tools/build-libbox-aar.sh            # только AAR
#   ./tools/build-libbox-aar.sh --with-apk # AAR + ./gradlew assembleDebug (нужен gradle/JDK)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NATIVE="$ROOT/native"
OUT="$ROOT/android/app/libs/flicker-box.aar"
GOMOBILE_VERSION="v0.1.12"   # версия из go.mod sing-box v1.14.2
NDK_REQUIRED="27.2.12479018" # единая версия NDK: здесь, build.gradle.kts и android.yml
# ---------------------------------------------------------------------------
#  ABI. Все четыре цели, которые поддерживает gomobile-форк sagernet v0.1.12:
#    platformArchs("android") = arm, arm64, 386, amd64
#    ndkConfig: arm → armeabi-v7a, arm64 → arm64-v8a,
#               386 → x86, amd64 → x86_64   (minAPI 21)
#
#  БЫЛО: TARGETS="android/arm64,android/amd64"
#        → 32-битные телефоны (armeabi-v7a) не покрыты. На них в APK нет
#          ни одной .so, System.loadLibrary("flickerbox") кидает
#          UnsatisfiedLinkError, и приложение не запускается.
#
#  ЦЕНА: каждая ABI — это полная компиляция sing-box со всеми зависимостями
#  (gvisor, quic-go, tailscale-mod, smux). Четыре цели вместо двух:
#    * время:  примерно вдвое больше (на 4-ядерной машине ~30-50 минут);
#    * память: нужно ~8-12 ГБ RAM, на 4 ГБ не влезет;
#    * диск:   ~12-16 ГБ (кэш Go-модулей 2.6-3.8 ГБ + промежуточные объекты).
#  Если ресурсы не тянут — собери в два захода: сначала arm64+arm, потом amd64+386.
#
#  Переопределяется из окружения:  TARGETS="android/arm64" ./tools/build-libbox-aar.sh
# ---------------------------------------------------------------------------
TARGETS="${TARGETS:-android/arm64,android/arm,android/amd64,android/386}"
LIBNAME="flickerbox"   # -> libflickerbox.so, loadLibrary("flickerbox")
TAGS="with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_low_memory,badlinkname,tfogo_checklinkname0"

log()  { printf '\033[1;34m[aar]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[ошибка]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 1. проверки ----------
command -v go >/dev/null || die "Go не найден в PATH (нужен 1.26+)"
GOVER="$(go env GOVERSION | sed 's/^go//')"
log "Go: $GOVER"

# JDK 17 (javac используется gomobile)
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVABIN="$JAVA_HOME/bin/java"
else
  JAVABIN="$(command -v java || true)"
fi
[ -n "$JAVABIN" ] || die "Java не найдена — нужен JDK 17 (temurin/openjdk)"
JVER="$("$JAVABIN" -version 2>&1 | head -1 || true)"
log "Java: $JVER"
case "$JVER" in
  *'"17'*) : ;;
  *) log "ВНИМАНИЕ: тулчейн sing-box ожидает openjdk 17; при ошибках сборки поставьте JDK 17 и JAVA_HOME" ;;
esac

# NDK: сначала требуемая версия, потом любая установленная
NDK=""
for base in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
  [ -n "$base" ] && [ -d "$base" ] && { NDK="$base"; break; }
done
if [ -z "$NDK" ]; then
  for root in "${ANDROID_HOME:-}/ndk" "$HOME/Android/Sdk/ndk" "$HOME/Library/Android/sdk/ndk"; do
    [ -d "$root" ] || continue
    # требуемая версия — в приоритете
    if [ -d "$root/$NDK_REQUIRED" ]; then NDK="$root/$NDK_REQUIRED"; break; fi
    cand="$(ls -1d "$root"/*/ 2>/dev/null | sort -V | tail -1)"
    [ -n "$cand" ] && NDK="${cand%/}" && break
  done
fi
[ -n "$NDK" ] && [ -d "$NDK" ] || die "NDK не найден. Установите NDK $NDK_REQUIRED (SDK Manager → SDK Tools → NDK (Side by side) → Show Package Details) и/или задайте ANDROID_NDK_HOME"

# версию берём оттуда же, откуда её берёт gomobile: Pkg.Revision в source.properties
NDK_VER="$(sed -n 's/^Pkg.Revision *= *//p' "$NDK/source.properties" 2>/dev/null | tr -d ' \r')"
log "NDK: $NDK (${NDK_VER:-версия не определена})"
if [ "$NDK_VER" != "$NDK_REQUIRED" ]; then
  log "ВНИМАНИЕ: ожидается NDK $NDK_REQUIRED, найден ${NDK_VER:-?}."
  log "          android/app/build.gradle.kts содержит ndkVersion = \"$NDK_REQUIRED\","
  log "          поэтому при другом NDK Gradle-сборка APK попросит именно $NDK_REQUIRED."
  log "          Либо поставьте $NDK_REQUIRED, либо поменяйте ndkVersion в build.gradle.kts."
fi
export ANDROID_NDK_HOME="$NDK"
export ANDROID_NDK_ROOT="$NDK"

# ---------- 2. gomobile (форк sagernet — как у sing-box) ----------
GOBIN="$(go env GOPATH)/bin"
if [ ! -x "$GOBIN/gomobile" ] || [ ! -x "$GOBIN/gobind" ]; then
  log "устанавливаю gomobile/gobind $GOMOBILE_VERSION (github.com/sagernet/gomobile)…"
  go install "github.com/sagernet/gomobile/cmd/gomobile@$GOMOBILE_VERSION"
  go install "github.com/sagernet/gomobile/cmd/gobind@$GOMOBILE_VERSION"
fi
export PATH="$GOBIN:$PATH"

# ---------- 3. bind ----------
mkdir -p "$(dirname "$OUT")"
cd "$NATIVE"
log "gomobile bind: ./mobile + sing-box/experimental/libbox → $TARGETS"
log "теги: $TAGS"
# ВНИМАНИЕ: без with_utls/with_gvisor Reality и userspace-сеть не компилируются.
# Два таргета → в AAR появятся jni/arm64-v8a/ и jni/x86_64/, т.е. APK соберётся
# и для телефона (arm64-v8a), и для эмулятора Android Studio (x86_64).
gomobile bind -v \
  -trimpath -buildvcs=false \
  -target "$TARGETS" \
  -androidapi 24 \
  -javapkg dev.flicker \
  -libname "$LIBNAME" \
  -tags "$TAGS" \
  -ldflags "-s -w" \
  -o "$OUT" \
  ./mobile github.com/sagernet/sing-box/experimental/libbox

[ -f "$OUT" ] || die "AAR не создан"
SIZE="$(du -h "$OUT" | cut -f1)"
log "готово: $OUT ($SIZE)"

# ---------- 3b. обязательная проверка содержимого AAR ----------
# Без неё легко получить APK, который ставится и падает на части устройств:
# abiFilters в Gradle только ФИЛЬТРУЕТ то, что уже лежит в AAR. Если цели не
# хватило, Gradle соберёт сплит без .so — и никаких ошибок сборки не будет.
log "проверяю ABI внутри AAR…"
FOUND="$(unzip -l "$OUT" | grep -oE 'jni/[a-z0-9_-]+/lib'"$LIBNAME"'\.so' | sort -u || true)"
echo "$FOUND" | sed 's/^/    /'
WANT="arm64-v8a armeabi-v7a x86_64 x86"
MISSING=""
for abi in $WANT; do
  echo "$FOUND" | grep -q "jni/$abi/" || MISSING="$MISSING $abi"
done
if [ -n "$MISSING" ]; then
  log "ВНИМАНИЕ: в AAR нет:$MISSING"
  log "          соответствующие сплиты соберутся ПУСТЫМИ и упадут с UnsatisfiedLinkError."
  log "          Либо убери эти ABI из ndk.abiFilters в android/app/build.gradle.kts,"
  log "          либо пересобери AAR с полным TARGETS."
else
  log "все четыре ABI на месте"
fi

# ---------- 3c. выравнивание .so (критично при useLegacyPackaging = false) ----------
# android/app/build.gradle.kts держит useLegacyPackaging = false, то есть
# extractNativeLibs="false": .so маппится в память прямо из APK и ОБЯЗАНА быть
# выровнена по границе страницы. На Android 15+ с 16-килобайтной страницей
# требуется Align = 0x4000; при 0x1000 dlopen падает и приложение не стартует.
if command -v readelf >/dev/null 2>&1; then
  TMPD="$(mktemp -d)"
  unzip -q -o "$OUT" -d "$TMPD" 'jni/*' 2>/dev/null || true
  for so in $(find "$TMPD/jni" -name '*.so' 2>/dev/null | sort); do
    A="$(readelf -lW "$so" 2>/dev/null | awk '/^ *LOAD/{print $NF; exit}')"
    abi="$(basename "$(dirname "$so")")"
    case "$A" in
      0x4000) log "  $abi: LOAD Align=$A — 16KB OK" ;;
      *)      log "  ВНИМАНИЕ $abi: LOAD Align=${A:-?} — НЕ 16 КБ."
              log "           На Android 15+ с 16KB-страницей dlopen упадёт."
              log "           Обход: useLegacyPackaging = true в app/build.gradle.kts" ;;
    esac
  done
  rm -rf "$TMPD"
fi

# ---------- 4. (опционально) APK ----------
if [ "${1:-}" = "--with-apk" ]; then
  cd "$ROOT/android"
  [ -x ./gradlew ] || chmod +x ./gradlew
  log "собираю APK (assembleDebug)…"
  ./gradlew --no-daemon :app:assembleDebug
  log "APK: android/app/build/outputs/apk/debug/app-debug.apk"
fi

log "дальше: откройте android/ в Android Studio и соберите APK (см. android/BUILD-ANDROID.md)"
