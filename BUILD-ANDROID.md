# Сборка Flicker VPN для Android

Цель документа: чтобы вы открыли `android/` в Android Studio и собрали APK,
**не угадывая версии**. Все числа ниже сверены с фактическими файлами проекта
и с официальными release notes AGP 8.7.0.

Целевые ABI: **arm64-v8a** (устройства) и **x86_64** (эмулятор Android Studio).
Минимум: **Android 7.0 / API 24**.

> Лицензия: GPL-3.0-or-later (см. `LICENSE`). Внутри — sing-box (libbox), тоже
> GPL-3.0. Распространяя APK, вы обязаны предоставлять исходники (раздел 7).

---

## 0. Точные версии — ставьте ровно эти

| Компонент | Версия | Откуда известно / зачем |
|---|---|---|
| **JDK** | **17** (Temurin или OpenJDK) | AGP 8.7: minimum JDK 17, default JDK 17. `compileOptions` и `kotlinOptions.jvmTarget` в проекте = 17. Тулчейн sing-box тоже ждёт openjdk 17 |
| **Android Gradle Plugin** | **8.7.3** | задан в `android/build.gradle.kts` |
| **Gradle** | **8.9** | задан в `gradle/wrapper/gradle-wrapper.properties`. AGP 8.7 требует minimum 8.9 — совпадает впритык, не понижайте |
| **Kotlin** | **1.9.24** | задан в `android/build.gradle.kts` |
| **NDK** | **27.2.12479018** | зафиксирован в `app/build.gradle.kts` (`ndkVersion`), в `tools/build-libbox-aar.sh` и в `.github/workflows/android.yml`. ⚠️ Дефолт AGP 8.7 — `27.0.12077973`, он **не** подойдёт: Gradle потребует ровно ту версию, что в `ndkVersion` |
| **compileSdk / targetSdk** | **35** | AGP 8.7 поддерживает максимум API 35 |
| **minSdk** | **24** | совпадает с `-androidapi 24` в `gomobile bind` |
| **SDK Build Tools** | **≥ 34.0.0** | AGP 8.7: minimum и default = 34.0.0 |
| **Go** | **1.26+** | `native/go.mod` содержит `go 1.26.0`. Проверено на go1.26.8 |
| **gomobile** | **v0.1.12** (форк `github.com/sagernet/gomobile`) | ровно эта версия в `go.mod` sing-box v1.14.2: `github.com/sagernet/gomobile v0.1.12` |

### SDK-компоненты (SDK Manager → вкладки)

**SDK Platforms:**
- Android 15.0 (API 35) — «Android SDK Platform 35»

**SDK Tools** (включите «Show Package Details», чтобы выбрать точную версию NDK):
- Android SDK Build-Tools **34.0.0** (или новее)
- Android SDK Platform-Tools
- Android SDK Command-line Tools (latest)
- **NDK (Side by side) → 27.2.12479018** ← именно эта, не «27.x любая»
- CMake — **не требуется**: в проекте нет `externalNativeBuild`, нативное ядро
  собирается отдельно через `gomobile`, а не через Gradle

**Эмулятор (только если хотите x86_64):**
- Android Emulator + системный образ **x86_64** (API 24+; рекомендуется API 34/35 Google APIs)

Проверить из терминала, что стоит нужное:

```bash
sdkmanager --list_installed | grep -E "ndk|platforms;android-35|build-tools"
# ожидается в том числе:
#   ndk;27.2.12479018
#   platforms;android-35
#   build-tools;34.0.0
```

---

## 1. Шаг первый (обязательный): собрать `flicker-box.aar`

**Без этого файла Gradle sync упадёт** с `Could not find libs/flicker-box.aar` —
это ожидаемо, а не баг. Файл бинарный (~40–90 МБ) и в git не коммитится
(`android/.gitignore` содержит `app/libs/*.aar`).

AAR = sing-box libbox + Go-фасад `native/mobile` одним файлом. Собирается
**не** Gradle'ом, а `gomobile bind`.

```bash
# из корня репозитория (рядом с android/ и native/)
export JAVA_HOME=<путь к JDK 17>
export ANDROID_NDK_HOME=<путь к SDK>/ndk/27.2.12479018
./tools/build-libbox-aar.sh
```

Ожидаемый вывод:

```
[aar] Go: 1.26.8
[aar] Java: openjdk version "17.0.x" ...
[aar] NDK: /…/ndk/27.2.12479018 (27.2.12479018)
[aar] устанавливаю gomobile/gobind v0.1.12 (github.com/sagernet/gomobile)…
[aar] gomobile bind: ./mobile + sing-box/experimental/libbox → android/arm64,android/amd64
[aar] теги: with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_low_memory,badlinkname,tfogo_checklinkname0
[aar] готово: …/android/app/libs/flicker-box.aar (NN МБ)
```

Первая сборка — **10–25 минут** на нормальной машине (компиляция всего sing-box
в двух архитектурах). Нужно ~8 ГБ RAM и ~8 ГБ диска.

Результат, который стоит проверить руками:

```bash
unzip -l android/app/libs/flicker-box.aar | grep -E "jni/|classes.jar"
# ожидается ДВЕ директории нативных библиотек:
#   jni/arm64-v8a/libflickerbox.so
#   jni/x86_64/libflickerbox.so
```

Если `jni/x86_64/` нет — эмулятор x86_64 упадёт с `UnsatisfiedLinkError`.
Значит, AAR собран старым скриптом с `-target android/arm64`; пересоберите.

Имя `.so` задаётся флагом `-libname flickerbox`, и оно **обязано** совпадать с
`System.loadLibrary("flickerbox")` в `FlickerApp.kt`. Сейчас совпадает.

### Точная команда bind (для справки / ручного запуска)

```bash
cd native
gomobile bind -v \
  -trimpath -buildvcs=false \
  -target android/arm64,android/amd64 \
  -androidapi 24 \
  -javapkg dev.flicker \
  -libname flickerbox \
  -tags "with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_low_memory,badlinkname,tfogo_checklinkname0" \
  -ldflags "-s -w" \
  -o ../android/app/libs/flicker-box.aar \
  ./mobile github.com/sagernet/sing-box/experimental/libbox
```

Все использованные флаги существуют в `sagernet/gomobile v0.1.12`
(`-o -gcflags -ldflags -target -bundleid -androidapi -a -i -trimpath -tags
-buildvcs` зарегистрированы в `cmd/gomobile/build.go:addBuildFlags`, `-javapkg -prefix
-classpath -bootclasspath -libname` — в `cmd/gomobile/bind.go`, `-v` — в
`addBuildFlagsNVXWork`). Имена целей `android/arm64` и `android/amd64` валидны:
`platformArchs("android") = {arm, arm64, 386, amd64}`, а `ndkConfig` сопоставляет
`arm64 → abi arm64-v8a (minAPI 21)` и `amd64 → abi x86_64 (minAPI 21)`.

> ⚠️ Не убирайте `with_utls` и `with_gvisor`: без первого молча исчезнет
> Reality/uTLS, без второго — userspace-сеть. `tfogo_checklinkname0` имеет
> смысл только на кастомной сборке Go от sagernet (tfogo); на обычном Go это
> просто неиспользуемый тег — Go не считает ошибкой неизвестный build-тег.

---

## 1.5. v4.12.0: нативные библиотеки обхода DPI (собираются автоматически)

С v4.12.0 режим «Обход DPI» — это порт рабочей схемы из
[EwenLoy/ByeByeDPI-x-tg v1.0.1-build5](https://github.com/EwenLoy/ByeByeDPI-x-tg/releases/tag/v1.0.1-build5)
(подробности: `DPI-INTEGRATION.md`). Для него из исходников собираются ДВЕ
нативные библиотеки:

* `libbyedpi.so` — сам обходчик DPI, hufrea/byedpi 17.3 (commit `e0fccf68` —
  pinned-submodule эталона). Исходники: `app/src/main/cpp/byedpi/`, JNI-обёртка
  `app/src/main/cpp/native-lib.c`. Собирается CMake через `externalNativeBuild`
  (автоматически при сборке APK).
* `libhev-socks5-tunnel.so` — tun2socks (TUN → SOCKS5). Исходники:
  `app/src/main/jni/hev-socks5-tunnel/` (дерево с hev-socks5-core,
  hev-task-system, lwip, yaml). Собирается задачей **`runNdkBuild`**
  (ndk-build), которая висит на `preBuild.dependsOn` и запускается САМА при
  каждой сборке. Вывод — в `app/src/main/hevlibs/<abi>/` (отдельная папка:
  ndk-build чистит выходной каталог, а в `jniLibs` лежит libflickerbox.so).

Ручных шагов нет; требуется лишь уже обязательный (с v4.7.0) NDK
**27.2.12479018** и CMake **3.22.1**. После сборки проверьте содержимое APK:

```bash
unzip -l app/build/outputs/apk/debug/app-debug.apk | grep "\.so"
# ожидается в lib/arm64-v8a/:
#   libflickerbox.so         — Go-ядро sing-box (VPN-режимы)
#   libbyedpi.so             — обход DPI (~100 КБ)
#   libhev-socks5-tunnel.so  — tun2socks обхода DPI (~1 МБ)
#   libtgwsproxy.so          — Telegram-туннель (Rust)
```

Если `libbyedpi.so` / `libhev-socks5-tunnel.so` в APK нет — режим «Обход DPI»
при подключении покажет явную ошибку «Библиотеки обхода DPI не загружены»
(и напишет подробности в отчёт).

## 2. Шаг второй: собрать APK в Android Studio

1. Убедитесь, что `android/app/libs/flicker-box.aar` существует (шаг 1).
2. Android Studio **Ladybug 2024.2.1 или новее** → **Open** → каталог `android/`.
   (Ladybug 2024.2.1 идёт с AGP 8.7 по умолчанию — совпадает с проектом.)
3. Если Studio спросит про JDK: **Settings → Build, Execution, Deployment →
   Build Tools → Gradle → Gradle JDK** → выбрать **17** (обычно «jbr-17»
   встроенный).
4. Дождитесь Gradle Sync. Первый раз скачает Gradle 8.9, AGP 8.7.3 и
   зависимости androidx — нужен интернет, 3–10 минут.
5. **Build → Build App Bundle(s) / APK(s) → Build APK(s)**.

Результат: `android/app/build/outputs/apk/debug/app-debug.apk`.

То же из терминала:

```bash
cd android
./gradlew :app:assembleDebug      # debug
./gradlew :app:assembleRelease    # release (подписан DEBUG-ключом!)
```

### Подпись release

Сейчас release намеренно подписывается debug-ключом
(`signingConfig = signingConfigs.getByName("debug")`), чтобы APK можно было
сразу поставить на телефон. Для распространения замените на свой keystore:

```kotlin
signingConfigs {
    create("release") {
        storeFile = file(System.getenv("FLICKER_KEYSTORE") ?: "flicker.jks")
        storePassword = System.getenv("FLICKER_STORE_PASS")
        keyAlias = "flicker"
        keyPassword = System.getenv("FLICKER_KEY_PASS")
    }
}
// и в buildTypes.release:
signingConfig = signingConfigs.getByName("release")
```

---

## 3. Альтернатива: CI (GitHub Actions)

`.github/workflows/android.yml`: ручной запуск (*Actions → Android → Run
workflow*) или push в `native/**` / `android/**`. На `ubuntu-latest`:

1. JDK 17 (temurin) + Go по `native/go.mod` + NDK **27.2.12479018**;
2. Go-тесты ядра;
3. `gomobile bind` → `flicker-box.aar`;
4. `./gradlew :app:assembleDebug :app:assembleRelease`;
5. Артефакты: **FlickerVPN-android-apk**, **flicker-box-aar**,
   **FlickerVPN-android-sources** (требование GPL).

⚠️ В CI шаг bind объявлен как «arm64-v8a» и использует `-target android/arm64`,
то есть **CI-артефакт не содержит x86_64** — на эмуляторе он не запустится.
Если нужен эмуляторный APK из CI, поменяйте в workflow `-target android/arm64`
на `-target android/arm64,android/amd64` (и имя шага). Локальный
`tools/build-libbox-aar.sh` уже собирает обе ABI.

---

## 4. Установка

1. Скопируйте APK на устройство (или `adb install app-debug.apk`).
2. Разрешите установку из неизвестных источников.
3. Первое подключение: системный диалог «Запрос VPN-подключения» → ОК.
4. Уведомления: на Android 13+ приложение запрашивает `POST_NOTIFICATIONS`
   при старте — разрешите, иначе не увидите статус туннеля.

Проверка: подключитесь к живому узлу и откройте `https://2ip.io` — IP должен
смениться на exitIp узла.

Диагностика: `adb logcat -s FlickerVPN` (тег всех логов, включая `box:` —
сообщения sing-box).

---

## 5. Что было исправлено при подготовке (конкретные правки)

Ниже — ошибки, которые **не дали бы собраться или нормально работать**.
Каждая подтверждена фактически (см. раздел 6).

| # | Файл | Было | Стало | Почему это ошибка |
|---|---|---|---|---|
| 1 | `app/build.gradle.kts` | `buildFeatures { viewBinding = true }` | добавлено `buildConfig = true` | С AGP 8.0 `BuildConfig` **не генерируется** по умолчанию. В коде 3 обращения (`FlickerApp.kt` ×2, `MainActivity.kt` ×1) → `unresolved reference: BuildConfig`, компиляция падает |
| 2 | `TunnelService.kt:439` | `NetworkCapabilities.NET_CAPABILITY_NOT_CONSTRAINED` | `val constrained = false` | Такой константы **нет в Android SDK**. `javap` по `android-35/android.jar` даёт только `NOT_CONGESTED, NOT_METERED, NOT_RESTRICTED, NOT_ROAMING, NOT_SUSPENDED, NOT_VPN` → `unresolved reference` |
| 3 | `TunnelService.kt:603` | `ServiceInfo.FOREGROUND_SERVICE_TYPE_VPN` | `ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST` | Константы `FOREGROUND_SERVICE_TYPE_VPN` **не существует**. Для VPN-сервиса нужен `…_MANIFEST` (API 29+): он указывает системе взять тип из `android:foregroundServiceType="vpn"` в манифесте |
| 4 | `Repository.kt:246` | `Mobile.fetchSubscriptions(…, 25L, …)` | `…, 25, …` | В Go `timeoutSeconds int` → Java `int` → Kotlin `Int`. Передача `Long` → `type mismatch` |
| 5 | `AndroidManifest.xml` | не было `FOREGROUND_SERVICE_VPN` | разрешение добавлено | При `targetSdk 34+` запуск FGS с типом `vpn` без этого разрешения падает в **рантайме** с `SecurityException` (компиляции не мешает — тем опаснее) |
| 6 | `app/build.gradle.kts` | `abiFilters += "arm64-v8a"`, `ndkVersion` отсутствует | `abiFilters += listOf("arm64-v8a", "x86_64")`, `ndkVersion = "27.2.12479018"` | x86_64 нужен для эмулятора; без явного `ndkVersion` Gradle берёт дефолт AGP (27.0.12077973) и расходится с CI |
| 7 | `tools/build-libbox-aar.sh` | `-target android/arm64` | `-target android/arm64,android/amd64` + проверка версии NDK по `Pkg.Revision` | Иначе в AAR нет `jni/x86_64/` и `abiFilters` с x86_64 даёт APK, который падает на эмуляторе |
| 8 | `native/mobile/mobile.go`, `native/cmd/flicker-host/main.go`, `mobile_test.go` | `4.0.0` | `4.0.1` | Расширение подписано как 4.0.1; `Mobile.version()` показывается в «О программе» — версии должны совпадать |

Попутно: убран избыточный `!!` в `ServerAdapter.kt:67` (после `row.ping != null`
срабатывает smart-cast; kotlinc выдавал warning).

### Про `usesCleartextTraffic` и `networkSecurityConfig`

**Не добавлены — и намеренно.** В Kotlin/Java-коде приложения нет ни одного
сетевого вызова: проверено grep'ом на `HttpURLConnection`, `OkHttp`,
`java.net.URL`, `Retrofit`, `WebView`, `openConnection`, `Socket(` — совпадений
ноль. Весь трафик, включая HTTP-пробы живости узлов, идёт внутри Go-ядра
(`native/mobile` → `internal/probe`) и через туннель libbox. Политика cleartext
платформы Android на Go-сокеты не распространяется, поэтому
`network_security_config.xml` был бы мёртвым файлом.

Если позже появится сетевой код на стороне Kotlin (например, WebView или свой
HTTP-клиент) — тогда `networkSecurityConfig` потребуется добавить.

---

## 6. Что проверено фактически, а что нет

### Проверено (с указанием способа)

**Компиляция Kotlin — реально выполнена.** Подняты JDK 17.0.20.1, kotlinc
**1.9.24** (та же версия, что в `build.gradle.kts`), `android.jar` **API 35**
(из официального `platform-35_r02.zip`), 45 артефактов androidx/material/
coroutines с `dl.google.com` и Maven Central. Для `dev.flicker.libbox` и
`dev.flicker.mobile` сгенерированы Java-stub'ы по правилам gobind, взятым из
исходников `sagernet/gomobile v0.1.12`, и по сигнатурам из
`sing-box@v1.14.2/experimental/libbox/*.go`. Результат:

```
kotlinc -cp <stubs:android-35:androidx…> -jvm-target 17 dev/flicker/vpn/*.kt
exit=0, 42 class-файла, 0 ошибок, 0 предупреждений
```

Тем же прогоном **найдены** ошибки №2, №3 и №4 из таблицы выше (до правок
компилятор выдал ровно их).

**API libbox сверен с первоисточником, а не по памяти:**
- `PlatformInterface` в `experimental/libbox/platform.go` содержит **31 метод**
  (не 27). Все 31 присутствуют в `TunnelService.kt` как `override` — проверено
  поштучно;
- правила именования gobind: `javaNameReplacer(lowerFirst(GoName))`
  (`bind/genjava.go:773, 844, 1539`) → `GetInet4Address` ⇒ `getInet4Address` ✓;
- поля структур → `public final native <T> get<Field>() / set<Field>(<T>)`
  с **Go-регистром имени** (`bind/genjava.go:318-323`) → `ni.setMTU(…)`,
  `options.getMTU()` ✓;
- конструктор без аргументов генерируется для структур, у которых нет
  Go-конструкторов (`bind/genjava.go:305-310`) → `BoxNetworkInterface()`,
  `SystemProxyStatus()`, `OverrideOptions()`, `SetupOptions()` валидны ✓;
- Java-генератор **не emit'ит** `@Nullable`/`@NonNull` (они есть только в
  `bind/genobjc.go`) → все типы для Kotlin платформенные, поэтому
  `WIFIState?`, `String?`, `ConnectionOwner?` в override законны ✓;
- Go `error` → `throws Exception` (`bind/genjava.go:855-857`); в Kotlin
  checked-exceptions нет → отсутствие `throws` в override не ошибка ✓;
- `CommandServerHandler` (7 методов), `FetchListener`, `ProbeListener`,
  `SocketProtector`, `InterfaceUpdateListener` (включая `updateNetworkPath`),
  `NetworkInterfaceIterator`, `RoutePrefixIterator`, `StringIterator`
  (`len/hasNext/next`), `TunOptions`, `StringBox.value`, `ShellSession`,
  `BridgeSession`, `Libbox.setup`, `Libbox.newCommandServer(handler, platform)`
  — порядок аргументов совпадает ✓;
- все 14 вызовов `Mobile.*` из Kotlin совпадают с 18 экспортированными
  функциями `native/mobile/mobile.go`; `int64` ↔ `Long`
  (`System.currentTimeMillis()`, `PRUNE_MAX_AGE_MS`) и `int` ↔ `Int` ✓.

**Ресурсы:** все `R.string` (41), `R.color` (10), `R.drawable` (11), `R.layout`
(3), `R.menu`, `R.id` (22) существуют; форматные аргументы совпадают
(`status_probing` = `%1$d/%2$d` ← два `Int`; `about_text` = `%1$s … %2$s` ← два
`String`). Все `binding.*` в `MainActivity`/`ServerAdapter` совпадают с ID и
типами вьюх в `activity_main.xml`/`item_server.xml`. `android.R.string.ok` /
`.cancel` — системные, присутствуют.

**Gradle/манифест:** Gradle wrapper 8.9 = минимум для AGP 8.7 ✓; compileSdk 35
= максимум для AGP 8.7 ✓; JDK 17 = минимум и дефолт AGP 8.7 ✓;
`foregroundServiceType="vpn"` + `BIND_VPN_SERVICE` на сервисе +
`intent-filter android.net.VpnService` ✓; `System.loadLibrary("flickerbox")`
соответствует `-libname flickerbox` ✓; `proguard-rules.pro` держит keep-правила
для всех пяти интерфейсов, `isMinifyEnabled = false` ✓.

**Go-ядро:** `gofmt` чисто, `go vet -tags "with_utls with_gvisor"` чисто,
`go test ./...` — все пакеты ok, **кроме** `TestSpeedMatryoshkaVsPlainVless`
(см. ниже). Кросс-компиляция `GOOS=android GOARCH=arm64 CGO_ENABLED=0` проходит.

**Build-теги AAR** существуют: `with_gvisor` (37 файлов), `with_quic` (14),
`with_wireguard` (2), `with_utls` (5), `with_clash_api` (2), `badlinkname` (29)
в sing-box; `with_low_memory` (4 файла) — в зависимостях `sagernet/*`.

### НЕ проверено (честно)

1. **`gomobile bind` не выполнялся.** В песочнице 2 CPU, ~3 ГБ свободного диска
   и нет NDK (нужно ~6–8 ГБ и сам NDK ~3 ГБ в распакованном виде). Поэтому:
   - не подтверждено, что AAR реально собирается и что в нём появятся
     `jni/arm64-v8a/` **и** `jni/x86_64/`;
   - не подтверждено, что sing-box v1.14.2 компилируется под **android/amd64**.
     Известно только, что `GOOS=android GOARCH=amd64 CGO_ENABLED=0` **не**
     проходит: Go отвечает
     `android/amd64 requires external (cgo) linking, but cgo is not enabled`.
     `gomobile bind` всегда включает cgo, поэтому ожидаемо соберётся, но это
     **вывод, а не результат прогона**. Если x86_64 не соберётся — уберите
     `android/amd64` из `-target` и `x86_64` из `abiFilters`, arm64 продолжит
     работать;
   - точные имена/сигнатуры сгенерированных Java-классов восстановлены по
     исходникам генератора, а не по реальному выводу gobind. Если bind выдаст
     иное имя, kotlinc укажет на него при первой же сборке.

2. **Gradle-сборка не выполнялась** (нет Android SDK, лицензии, эмулятора).
   Синтаксис Kotlin DSL (`ndkVersion = …`, `abiFilters += listOf(…)`,
   `buildConfig = true`) соответствует AGP 8.7, но `./gradlew assembleDebug`
   здесь не запускался.

3. **Работа на устройстве/эмуляторе не проверялась** — туннель, protect(fd),
   watchdog, автопереключение. Десктопная часть протоколов проверена живыми
   серверами (см. `ОТЧЕТ.md`), Android-туннель — нет.

4. **`TestSpeedMatryoshkaVsPlainVless` падает в песочнице** и это
   **не связано** с правками выше: тест замеряет пропускную способность
   «матрёшки» WG-в-VLESS и валится при `mbpsB < 30`. Здесь вышло 23.1, затем
   18.2 Мбит/с — на 2 CPU это потолок userspace-WG+netstack. Все остальные
   тесты `internal/tunnel` проходят (`ok 0.094s`). Тест не гейтится ни
   `-short`, ни переменной окружения, поэтому `tests/run-all.sh` (он вызывает
   `go test ./...`) на слабой машине покажет 1 провал. Лечится запуском на
   нормальном CPU либо гейтом вида
   `if os.Getenv("FLICKER_SPEED_TEST") == "" { t.Skip(...) }` — на ваше
   усмотрение, я это не менял.

---

## 7. GPL-3.0: обязательства

- Приложение и `flicker-box.aar` (производное от sing-box) — **GPL-3.0**.
- Распространяя APK/AAR, приложите полные соответствующие исходники:
  `native/` (Go) и `android/` (Kotlin/Gradle) + тексты лицензий
  (`native/COPYING`, `android/LICENSE`, `native/LICENSE-NOTES.md`).
- CI-артефакт `FlickerVPN-android-sources` содержит ровно их.
- В приложении меню «О программе» показывает версию и лицензию — замените URL
  репозитория в `res/values/strings.xml` на свой.

---

## 8. Ограничения и особенности

- **Реальность и PQ (X25519MLKEM768):** как на десктопе — Reality-клиент
  sing-box фильтрует PQ-наборы; целевой сайт Reality-сервера не должен быть
  PQ-only (подробности в `ОТЧЕТ.md`).
- **«Матрёшка» (WG-в-VLESS)** медленнее прямого VLESS (двойная инкапсуляция).
- **IPv6** включается, если sing-box выдал v6-адреса TUN; иначе IPv4 +
  `fdfe:dcba:9876::1/126` (как SFA).
- **Watchdog** перепроверяет узел раз в 15 минут только при активном туннеле;
  фонового обновления подписок без открытого приложения нет (экономия батареи).
- `isMinifyEnabled = false` — gomobile JNI не переносит агрессивный R8 без
  аккуратных keep-правил (правила заготовлены в `proguard-rules.pro`).

---

## 9. Troubleshooting

| Симптом | Причина / лечение |
|---|---|
| `Could not find libs/flicker-box.aar` при sync | не выполнен шаг 1 |
| `unresolved reference: BuildConfig` | в `buildFeatures` нет `buildConfig = true` |
| `NDK not configured. Download it with SDK manager. Preferred NDK version is '27.2.12479018'` | поставьте ровно эту версию NDK (Show Package Details) |
| `java version should be openjdk 17` | JDK не 17; поставьте Temurin 17 и `export JAVA_HOME=…` |
| gomobile: `ndk: not found` | `export ANDROID_NDK_HOME=<sdk>/ndk/27.2.12479018` |
| `android/amd64 requires external (cgo) linking` | попытка собрать x86_64 с `CGO_ENABLED=0`; `gomobile bind` ставит cgo сам — не задавайте `CGO_ENABLED=0` вручную |
| `UnsatisfiedLinkError` на эмуляторе x86_64 | в AAR нет `jni/x86_64/` — пересоберите шаг 1 (нужен `-target android/arm64,android/amd64`) |
| bind падает по памяти | нужно ~8 ГБ RAM; закройте IDE или используйте CI |
| Приложение: «нативная библиотека не готова» | `loadLibrary("flickerbox")` не удался — AAR собран без тегов/не под вашу ABI |
| Подключение мгновенно падает | `adb logcat -s FlickerVPN` → строки `box:`; чаще всего мёртвый узел |
| `SecurityException … FOREGROUND_SERVICE_VPN` | в манифесте нет `<uses-permission android:name="android.permission.FOREGROUND_SERVICE_VPN"/>` |
