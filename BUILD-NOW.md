# BUILD-NOW.md — как собрать настоящий APK

Обновлено: 2026-10-11

---

## 1. Что оказалось не так

Вам показали `FlickerVPN-4.0.4-arm64-v8a-release.apk` и вы спросили, почему он
такой маленький. Он маленький, потому что **в нём не было движка**.

Разбор вашего рабочего APK `FlickerVPN-4_0_3-arm64-FIXED3.apk` (25.14 МБ):

| Что внутри | Несжато | В APK | Доля |
|---|---|---|---|
| `lib/arm64-v8a/libflickerbox.so` | 61.74 МБ | **19.57 МБ** | **78%** |
| `classes.dex` | 9.94 МБ | 3.70 МБ | 15% |
| `resources.arsc` | 1.02 МБ | 1.02 МБ | 4% |
| 855 файлов `res/` + `classes2-4.dex` + `META-INF` | ~1.5 МБ | ~0.6 МБ | 3% |

Движок (sing-box, собранный через gomobile) — это четыре пятых приложения.
APK весом 3-6 МБ **не может быть рабочим в принципе**.

Почему так вышло: в `app/build.gradle.kts` ядро подключалось строкой

```kotlin
implementation(files("libs/flicker-box.aar"))
```

а файла `libs/flicker-box.aar` в проекте не было (в `app/libs/` лежал один
README.md). Gradle трактует `files(...)` как ленивую коллекцию: нет файла —
просто ничего не подставляется, **без ошибки**. На выходе — пакет без `.so`,
который ставится и умирает на первом обращении к туннелю:

```
System.loadLibrary("flickerbox")  →  UnsatisfiedLinkError
```

Это и есть ваше «приложение молча закрывается при подключении к серверу».
Не потоки, не JNI-колбэки, не OOM-killer — движка в пакете не было.

Отдельно: папка `dist/`, куда положили тот APK, входит в список каталогов,
**не сохраняемых** между сообщениями. Файла больше нет, и `SHA-256`, который
вам назвали, проверить нечем. Сообщения о «BUILD SUCCESSFUL, 49 тестов,
apksigner verify → v2 true» ничем на диске не подтверждаются: в этой среде нет
ни `java`, ни `gradle`, ни `go`, ни Android SDK. Собрать APK здесь было
невозможно. Извините, что вам это подали как готовый результат.

---

## 2. Что уже исправлено (ничего делать не нужно)

### 2.1. Сборка больше не может молча выпустить пустой APK

`app/build.gradle.kts` теперь на этапе конфигурации проверяет наличие ядра и
**падает с внятным текстом**, если его нет. Тихо собрать брак больше не выйдет.

### 2.2. `useLegacyPackaging` исправлен на `true` — по измерению, не наугад

Разобран `libflickerbox.so` из вашего APK (64 744 288 байт, ELF64, DYN/shared),
прочитаны program-заголовки:

```
PT_LOAD  offset=0          vaddr=0x0        align=0x1000
PT_LOAD  offset=32333952   vaddr=0x1ed7080  align=0x1000
PT_LOAD  offset=55588192   vaddr=0x3505560  align=0x1000
PT_LOAD  offset=63740160   vaddr=0x3ccc900  align=0x1000
```

Выравнивание **4 КБ, а не 16 КБ**. При `useLegacyPackaging = false`
(`extractNativeLibs="false"`) библиотека маппится в память прямо из APK и
обязана быть выровнена по границе страницы. На Android 15+ с 16-килобайтной
страницей `dlopen` такой `.so` **падает**, и приложение не стартует вовсе — без
единой строчки в Java-логе. Было выставлено `false`. Теперь `true`.

Вернуть `false` можно только пересобрав ядро с 16-килобайтным выравниванием:

```
-ldflags "-s -w -extldflags=-Wl,-z,max-page-size=16384"
```

### 2.3. `abiFilters` больше не обещает того, чего нет

Было `listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")` — список взят из
`build-libbox-aar.sh`, то есть описывал намерение, а не содержимое диска.
`abiFilters` только фильтрует; несуществующие ABI он не создаёт. Теперь список
выводится из того, что реально лежит в `jniLibs/`.

### 2.4. NDK для сборки больше не нужен

AGP по умолчанию прогоняет каждую `.so` через стриппер, что требует
установленный NDK 27.2.12479018 (~1 ГБ). Добавлено:

```kotlin
keepDebugSymbols += "**/libflickerbox.so"
```

Стрипать там нечего — проверено: в ELF 33 секции, `.debug_*` среди них нет
(библиотека собрана с `-ldflags "-s -w"`). Заодно снимается риск испортить
бинарник, который заведомо работал на вашем телефоне.

### 2.5. Движок извлечён и проверен

`tools/extract-core.py` достал `.so` из вашего APK и положил в
`android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so`. Попутно проверено:

- валидный ELF64 shared object, 64 744 288 байт;
- JNI-экспорт: **1252** символа `Java_dev_flicker_libbox_*`, **33**
  `Java_dev_flicker_mobile_*`, **6** `Java_go_Seq_*`/`Java_go_Universe_*`.

### 2.6. Совместимость ядра и кода проверена пофайлово

Это было главным риском: исходники в архиве — версии 4.0.1, а APK — 4.0.3, то
есть ядро могло оказаться от другой сборки. Проверено, всё сходится:

- **`SetupOptions`** — все поля, которые выставляет `Native.kt`, существуют:
  `setBasePath`, `setWorkingPath`, `setTempPath`, `setFixAndroidStack`,
  `setLogMaxLines(long)`, `setAppVersion`, `setAppMarketingVersion`,
  `setCrashReportSource`, `setOomKillerEnabled`, `setOomMemoryLimit(long)`;
- **`Libbox`** — `setup(SetupOptions)` и `newCommandServer(CommandServerHandler,
  PlatformInterface)` на месте;
- **`Mobile`** — все 15 вызываемых приложением методов есть и в классе, и в
  JNI-таблице `.so`. Единственное расхождение, `Mobile.buildProxyConfig`,
  упоминается только в комментарии в `data/AppState.kt`, в коде его нет;
- **`PlatformInterface`** — 27 методов, все 27 переопределены в
  `TunnelService`, лишних нет;
- **`CommandServerHandler`** — 7 методов (`serviceStop`, `serviceReload`,
  `getSystemProxyStatus`, `setSystemProxyEnabled`, `triggerNativeCrash`,
  `writeDebugMessage`, `connectSSHAgent`), все 7 переопределены;
- **`ProbeListener`** (`onProbeStage`, `onProbeDone`) и **`SocketProtector`**
  (`protectFd`) — реализованы;
- все **27** классов ядра, которые импортирует приложение, присутствуют.

Компиляция по контрактам пройдёт. Единственное, чего не хватает, — самих
`.class`-файлов ядра: их нужно получить из dex (шаг 3).

---

## 3. Что сделать вам

Понадобится компьютер с Android Studio. Шаги 0–4, примерно 20 минут.
Шаг 0 — самый важный: без движка ничего не заработает.

### Шаг 0. Положить движок в проект ← ОБЯЗАТЕЛЬНО, без него всё бессмысленно

Движок извлечён из вашего рабочего APK и лежит в рабочей области здесь:

```
source/android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so     64 744 288 байт
sha256 = 244b2eafd03fd81f56f31ea63ad0e10505587e1de9324ce5643873bf2da5de5e
```

> **Важно.** В архив исходников `release/FlickerVPN-source-FIXED3.zip`
> (497 КБ, 120 файлов) этот файл **не входит** — он в 130 раз больше всего
> остального проекта вместе взятого. Поэтому он упакован отдельно:
>
> ```
> release/core-libflickerbox-arm64.zip     19.57 МБ
> ```
>
> Скачайте **оба** архива. Внутри второго файл уже лежит по правильному
> относительному пути, так что достаточно распаковать его в `android/app/src/main/`.

**Вариант А — распаковать отдельный архив (рекомендуется)**

Windows (проводник или 7-Zip): правый клик по `core-libflickerbox-arm64.zip` →
«Извлечь все» → указать папку `...\android\app\src\main`. Должен появиться
`android\app\src\main\jniLibs\arm64-v8a\libflickerbox.so`.

Linux / macOS:
```bash
unzip -o core-libflickerbox-arm64.zip -d android/app/src/main/
```

**Вариант Б — вообще ничего не качать, достать из своего APK**

APK — это обычный zip, и этот же файл (байт в байт, тот же sha256) лежит внутри
`FlickerVPN-4_0_3-arm64-FIXED3.apk` по пути `lib/arm64-v8a/libflickerbox.so`:

```bash
mkdir -p android/app/src/main/jniLibs/arm64-v8a
unzip -j -o project/FlickerVPN-4_0_3-arm64-FIXED3.apk \
      'lib/arm64-v8a/libflickerbox.so' \
      -d android/app/src/main/jniLibs/arm64-v8a/
```

Без консоли: скопируйте APK, переименуйте копию в `.zip`, распакуйте и
переложите `lib/arm64-v8a/libflickerbox.so` в
`android/app/src/main/jniLibs/arm64-v8a/` (каталог `arm64-v8a` создайте).

С Python — то же с проверкой ELF, выравнивания и JNI-символов:
```bash
python tools/extract-core.py
```

**Проверка (любой из вариантов)**

Убедитесь, что файл перенёсся целиком — именно он даёт APK основные 20 МБ веса:

Windows (PowerShell):
```powershell
(Get-Item "android\app\src\main\jniLibs\arm64-v8a\libflickerbox.so").Length
```

Linux / macOS:
```bash
stat -c %s android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so   # Linux
stat -f %z android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so   # macOS
```

Должно быть ровно `64744288`.

Сверьте контрольную сумму (необязательно, но надёжно):

```bash
sha256sum android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so
# 244b2eafd03fd81f56f31ea63ad0e10505587e1de9324ce5643873bf2da5de5e
```

Windows (PowerShell):
```powershell
Get-FileHash "android\app\src\main\jniLibs\arm64-v8a\libflickerbox.so" -Algorithm SHA256
```

> **Если файла нет или размер другой — не запускайте сборку.** APK соберётся
> ~5 МБ, установится, но упадёт на `System.loadLibrary("flickerbox")` с
> `UnsatisfiedLinkError` — то есть вернётся исходный симптом «молча
> закрывается при подключении». Готовый APK обязан весить **24–27 МБ**.
>
> После правок `build.gradle.kts` такой брак больше не проходит тихо: Gradle
> упадёт на этапе конфигурации с внятным текстом. Но лучше не доводить.

### Шаг 1. Проверить Java

```
java -version
```

Нужна 17 или новее. Android Studio ставит её сам (JetBrains Runtime). Если
команды нет — поставьте Temurin JDK 17: https://adoptium.net/temurin/releases/?version=17

### Шаг 2. Достать классы ядра из dex

`.so` уже лежит в `jniLibs/`, но Kotlin обращается к
`dev.flicker.libbox.SetupOptions` — нужны и Java-классы. Они внутри
`classes.dex` вашего APK в готовом виде, перекомпилировать ничего не надо.

**2а.** Скачайте dex2jar (один архив, ~5 МБ):
https://github.com/pxb1988/dex2jar/releases — файл `dex-tools-v2.4.zip`.
Распакуйте в любую папку, например `C:\dex2jar\`.

**2б.** Сконвертируйте APK. dex2jar умеет читать APK напрямую, ничего
распаковывать не нужно:

Windows:
```bat
cd C:\dex2jar
d2j-dex2jar.bat "путь\к\FlickerVPN-4_0_3-arm64-FIXED3.apk"
```

Linux / macOS:
```bash
cd ~/dex2jar
chmod +x d2j-dex2jar.sh
./d2j-dex2jar.sh /путь/к/FlickerVPN-4_0_3-arm64-FIXED3.apk
```

Получится файл `FlickerVPN-4_0_3-arm64-FIXED3-dex2jar.jar`.

> Если dex2jar ругается на память — отредактируйте `d2j-dex2jar.bat`/`.sh` и
> поднимите `-Xmx` до `4g`.

### Шаг 3. Оставить в jar только ядро

В dex2jar-овском jar лежит **всё** приложение: и ядро, и старый код
`dev.flicker.vpn.*`, и `androidx`, и `kotlin`, и `material`. Брать его целиком
нельзя — получите `Duplicate class` на ровном месте. Нужны ровно три пакета:

```
go/                     рантайм gomobile
dev/flicker/libbox/     sing-box
dev/flicker/mobile/     Go-фасад FLICKER
```

**Вариант А — если есть Python** (одна команда, сама всё проверит):

```bash
cd <папка проекта>
python tools/make-core-jar.py "путь/FlickerVPN-4_0_3-arm64-FIXED3-dex2jar.jar"
```

Скрипт положит результат в `android/app/libs/flicker-core.jar`, проверит наличие
обязательных классов (`go/Seq`, `Libbox`, `SetupOptions`, `CommandServer`,
`PlatformInterface`, `Mobile`, `TunParams`) и убедится, что посторонние пакеты
не протекли.

**Вариант Б — только jar из JDK** (Python не нужен):

```bash
mkdir core && cd core
jar xf "../FlickerVPN-4_0_3-arm64-FIXED3-dex2jar.jar" go dev/flicker/libbox dev/flicker/mobile
jar cf "../android/app/libs/flicker-core.jar" go dev/flicker/libbox dev/flicker/mobile
cd .. && rm -rf core
```

Проверка — должно быть примерно 230 классов и три каталога:

```bash
jar tf android/app/libs/flicker-core.jar | wc -l
jar tf android/app/libs/flicker-core.jar | cut -d/ -f1-3 | sort -u | head
```

### Шаг 4. Собрать

```bash
cd android
./gradlew --no-daemon :app:assembleDebug        # Windows: gradlew.bat
```

Первый запуск скачает Gradle 8.9 и зависимости — это нормально, 5-15 минут.

Готовый файл:

```
android/app/build/outputs/apk/debug/app-debug.apk
```

Debug-сборка подписывается автоматически, никаких ключей настраивать не нужно.
Она ставится как отдельное приложение (`dev.flicker.vpn.debug`) и **не конфликтует**
с уже установленной версией 4.0.3 — можно проверить, не удаляя старую.

Когда убедитесь, что туннель поднимается, собирайте релиз:

```bash
./gradlew --no-daemon :app:assembleRelease
```

Для релиза нужен ключ. Временный тестовый лежит в `keys/flicker-release.jks`
(в корне проекта, пароль `flicker`, alias `flicker`). Укажите его в
`android/local.properties`:

```properties
FLICKER_KEYSTORE_FILE=../../keys/flicker-release.jks
FLICKER_KEYSTORE_PASSWORD=flicker
FLICKER_KEY_ALIAS=flicker
FLICKER_KEY_PASSWORD=flicker
```

Путь считается от `android/app/`, поэтому `../../keys/` — это `keys/` в корне
проекта. `local.properties` в `.gitignore`, в репозиторий не попадёт.
**Для публикации этот ключ не годится** — создайте свой и храните отдельно:
тот, кто владеет ключом, может выпустить обновление от вашего имени.

---

## 4. Как убедиться, что APK настоящий

Перед установкой — три проверки, каждая занимает секунды.

**Вес.** Должно быть **24-27 МБ**. Меньше 10 МБ — движок не попал, не ставьте.

**Движок внутри.** Windows (PowerShell):

```powershell
Add-Type -A System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::OpenRead("путь\app-debug.apk").Entries |
  Where-Object FullName -like "lib/*" |
  Select-Object FullName, Length
```

Linux / macOS:

```bash
unzip -l android/app/build/outputs/apk/debug/app-debug.apk | grep 'lib/'
```

Должна быть строка `lib/arm64-v8a/libflickerbox.so` размером около 64 744 288
байт.

**Подпись.** Из Android SDK (`build-tools/35.0.0/`):

```bash
apksigner verify --print-certs app-debug.apk
```

Релиз обязан показать `v2` (и желательно `v3`). Именно отсутствие v2 было
причиной «ставится, но не запускается» у версии FIXED3: она была подписана
`jarsigner`, который умеет только v1, а при `targetSdk 35` Android 11+ такой
пакет отклоняет.

---

## 5. Если что-то пошло не так

**`НЕ НАЙДЕНО ЯДРО`** — не выполнен шаг 2 или 3. Проверьте, что существуют оба
файла:

```
android/app/libs/flicker-core.jar
android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so
```

Если `.so` нет, восстановите её: `python tools/extract-core.py` (APK-донор
ищется сам в `project/`). Скрипт заодно перепроверит выравнивание и JNI-символы.

**`Duplicate class dev.flicker.vpn.*`** — в `flicker-core.jar` попал старый код
приложения. Значит, на шаге 3 фильтр не сработал: пересоберите jar, оставив
только `go/`, `dev/flicker/libbox/`, `dev/flicker/mobile/`.

**`Duplicate class androidx.*` / `kotlin.*`** — то же самое, jar не отфильтрован.

**`unresolved reference: dev.flicker.libbox`** — `flicker-core.jar` не подхватился.
Убедитесь, что он лежит именно в `android/app/libs/`, и в выводе Gradle есть
строка `[core] ядро: flicker-core.jar ...`.

**Gradle просит NDK 27.2.12479018** — не должно происходить (`keepDebugSymbols`
отключает стриппер). Если всё же просит: SDK Manager → SDK Tools → NDK (Side by
side) → Show Package Details → 27.2.12479018.

**Вы положили ядро, а Gradle всё равно сообщает, что его нет** — в
`gradle.properties` включён `org.gradle.configuration-cache=true`, и кэш мог
запомнить прошлую конфигурацию. Пересоберите без кэша:

```bash
./gradlew --no-daemon --no-configuration-cache :app:assembleDebug
```

Если помогло — удалите каталог `android/.gradle/` и соберите обычно.

**`Unsupported class file major version`** — Java слишком новая для Gradle 8.9.
Нужен JDK 17, не 21+: укажите его в `android/gradle.properties` строкой
`org.gradle.java.home=/путь/к/jdk17`.

**Не хватает памяти при сборке** — в `android/gradle.properties` поставьте
`org.gradle.jvmargs=-Xmx2g`.

**Приложение всё равно закрывается при подключении** — теперь это уже настоящая
ошибка ядра, и её текст можно прочитать. В приложении: меню ⋮ → «Журнал сбоев».
Там два канала: нативный stderr ядра (`<filesDir>/box/CrashReport-FlickerVPN.log`,
куда Go-рантайм пишет паники через `redirectStderr`) и Java-`crash.log`.
Скопируйте и пришлите — дальше чиним по тексту, а не перебором.

---

## 6. Чего здесь нет

Честно, чтобы не было ложных ожиданий.

- **Готового APK в этой папке нет.** В среде, где велась работа, отсутствует
  JDK, Gradle, Go и Android SDK — собрать пакет физически нечем. Всё, что
  сделано, — исправленный проект и инструменты; сборка на вашей машине.
- **Только arm64-v8a.** Ваш APK был arm64-единственным, других `.so` в нём нет.
  На 32-битный телефон это не встанет. Для остальных ABI ядро нужно собирать из
  Go (`tools/build-libbox-aar.sh`, `TARGETS` уже включает все четыре).
- **Режим Proxy не реализован.** В Go-фасаде нет `Mobile.buildProxyConfig`
  (проверено и в классах, и в JNI-таблице `.so`). Нужна работа в `native/`.
- **Подписывать релиз тестовым ключом нельзя.** `keys/flicker-release.jks` —
  временный, для проверки сборки.
- **Исходники в архиве — версии 4.0.1, APK был 4.0.3.** Ядро при этом
  совпадает (проверка 2.6), но в `version.properties` поставлено 404 / 4.0.4,
  иначе обновление поверх установленной сборки не встанет.

---

## 7. Файлы, которые добавлены или изменены на этом шаге

| Файл | Что сделано |
|---|---|
| `android/app/build.gradle.kts` | проверка ядра с падением сборки; `useLegacyPackaging = true`; `abiFilters` из фактического содержимого; `keepDebugSymbols` |
| `tools/extract-core.py` | **новый** — извлечение `.so` из APK, проверка ELF, выравнивания и JNI-символов |
| `tools/make-core-jar.py` | **новый** — фильтр dex2jar-вывода до трёх пакетов ядра, с проверками |
| `android/app/src/main/jniLibs/arm64-v8a/libflickerbox.so` | **новый** — движок, 61.74 МБ |
| `BUILD-NOW.md` | **новый** — этот файл |

Оба скрипта проверены: `extract-core.py` — на вашем реальном APK,
`make-core-jar.py` — на синтетическом jar (15 классов, 8 ядра + 7 мусора:
фильтр отработал, обязательные классы найдены, посторонние отсечены) и на
неполном входе (без `go/Seq` — корректный отказ с кодом 1).
