# FIX-REPORT FlickerVPN Android 4.12.1

**Дата:** 10 ноября 2026  
**База:** 4.12.0 (исходники соответствуют APK 4.12.0)

## Исправленные баги

### Баг 5 — вылет после дохлых серверов
**Файлы:** `TunnelService.kt`, `BypassVpnService.kt`, `ByeDpiEngineService.kt`

- Удалён `Process.killProcess` из `stopTunnel()`: при зависании `closeService` — повторное `closeTunFdForced`, запись в `CrashLog`, `stopSelf()`.
- `forceTeardown()` больше не убивает процесс; возвращает `true` если интерфейс не снялся.
- `isAnyVpnUp()` при исключении возвращает `false` (раньше `true` → ложное убийство).
- `startTunnel().onFailure` продолжает перебор через `handleDeadNode`, а не обрывает цикл `stopSelf()`.
- Уведомление об исчерпании пула: «перебрано $autoSwitchCount».
- Убраны `killProcess` из `BypassVpnService.onDestroy` и `ByeDpiEngineService.terminate`.

### Баг 4 — нет выхода
**Файлы:** `MainActivity.kt`, `menu_main.xml`, `strings.xml`

- Пункт меню «Выход» + `confirmExit()`: `TunnelService.stop` + `finishAffinity()` (без hardStop/killProcess).

### Баг 2 — поиск кривой
**Файлы:** `ServerAdapter.kt`, `MainActivity.kt`, `Repository.kt`

- `ServerAdapter` → `ListAdapter` + `DiffUtil`, метод `filter()` (имя/хост/протокол).
- `SearchView` в меню (`action_search`).
- Кнопка «Проверить» неактивна при `ui.connected`; тост «Отключите VPN…»; пустой `toast` не показывается.
- `FETCH_LIMIT` 25 → **200**.

### Баг 3 — опции / DNS
**Файлы:** `Repository.kt`, `MainActivity.kt`

- Валидация DNS в `setDnsServer` (IPv4/IPv6).
- При сохранении настроек DNS пишется и в `Repository`, и в `Prefs.setBypassDns` (режим обхода DPI).

### Баг 1 — меню слабое
**Файлы:** `menu_main.xml`, `MainActivity.kt`

- Добавлены: Поиск, Настройки, Обновить подписки, Выход.
- Убран дублирующий пункт «Режим».

### Сплэш со змейками
**Файлы:** `SplashActivity.kt`, `activity_splash.xml`, `splash_glow.xml`, `shimmer_band.xml`, `ic_snake_tongue.xml`, `AndroidManifest.xml`

- LAUNCHER = `SplashActivity` (~1.9 с анимации) → `MainActivity`.
- `splash_snakes.png` уже был в 4.12.0 (`drawable-nodpi`).

## Версия
`VERSION_NAME=4.12.1`, `VERSION_CODE=4121`

## Сборка
На этой машине **не собиралось**: нет полного Android SDK/NDK/Go/gomobile окружения и `flicker-box.aar`.

На машине пользователя:
```bash
cd flicker-4.12.1-fixed
./check-env.sh
export JAVA_HOME=<JDK17>
export ANDROID_NDK_HOME=<SDK>/ndk/27.2.12479018
./tools/build-libbox-aar.sh
cd android && ./gradlew assembleDebug
```
APK: `android/app/build/outputs/apk/debug/app-debug.apk`

## Не проверено на устройстве
Сценарии багов 1–5 и сплэш на телефоне/эмуляторе не гонялись (нет устройства в среде агента).

## Замечания
- В комментариях ещё встречаются слова `killProcess` (исторические); **вызовов** `Process.killProcess(...)` в коде нет.
- `ByeDpiEngineService` раньше убивал процесс `:byedpi` для сброса JNI; теперь только `stopSelf` — при глюках byedpi после многих рестартов возможны артефакты, это осознанный компромисс против «вылета» UI.
