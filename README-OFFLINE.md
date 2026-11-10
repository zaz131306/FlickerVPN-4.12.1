# Сборка Android без GitHub и с плохим интернетом

GitHub не нужен вообще. CI-workflow был только запасным путём — всё делается
локально. Ниже: что у вас скорее всего уже есть, что придётся скачать, и как
обойти блокировки.

---

## Шаг 0. Запустите диагностику

```bash
bash check-env.sh
```

Скрипт ничего не ставит и не качает. Он покажет:

- какой у вас JDK (нужен 17) и Go (нужен 1.26+);
- **есть ли уже кэш Go-модулей с деревом sing-box** — это самый важный пункт;
- какой NDK установлен и есть ли нужный `27.2.12479018`;
- **замерит доступность и скорость** proxy.golang.org, goproxy.cn, goproxy.io,
  mirrors.aliyun.com, dl.google.com, services.gradle.org, repo1.maven.org,
  github.com — и посоветует самое быстрое зеркало.

Дальше действуйте по его выводу.

---

## Главная хитрость: GOPROXY

Самое тяжёлое в сборке — **2.6–3.8 ГБ Go-модулей** (дерево зависимостей
sing-box: gvisor, quic-go, tailscale-mod, smux и т.д.). По умолчанию Go ходит
на `proxy.golang.org`, который из РФ работает плохо.

Но Go умеет ходить через **любое** зеркало, и китайские зеркала обычно
прекрасно доступны из РФ и отдают модули быстро:

```bash
go env -w GOPROXY='https://goproxy.cn,direct'
# или, если диагностика показала, что aliyun быстрее:
go env -w GOPROXY='https://mirrors.aliyun.com/goproxy/,direct'
```

Проверить, что заработало:

```bash
cd native && go mod download all
```

Это единственная настройка, которая реально решает проблему «интернет жопа»
для Go-части.

---

## Что у вас, скорее всего, УЖЕ есть

В вашем исходном архиве лежали собранные ELF-бинарники `native/flicker-host`
(38 МБ) и `native/bin/server-generator`. Значит, Go-проект вы на своей машине
**уже собирали**, а следовательно:

- **Go 1.26+ установлен**;
- **кэш Go-модулей уже наполнен** (`go env GOMODCACHE`, обычно
  `~/go/pkg/mod`) — там уже лежит дерево sing-box, и 2.6 ГБ заново качать
  **не нужно**.

`check-env.sh` это подтвердит или опровергнет (ищет
`$GOMODCACHE/github.com/sagernet/`).

Если кэш есть — весь сетевой трафик на сборку AAR сводится к:

| Что | Откуда | Размер |
|---|---|---|
| `gomobile` + `gobind` v0.1.12 | `go install github.com/sagernet/gomobile/cmd/...@v0.1.12` → идёт через GOPROXY (зеркало), не через github.com | ~50 МБ |
| Android-специфичные модули | тот же GOPROXY | до ~1 ГБ (если вы собирали только под Linux) |

---

## Что придётся скачать (это уже Google, не GitHub)

| Что | Размер | Где взять |
|---|---|---|
| **JDK 17** | ~180 МБ | Adoptium Temurin 17; в РФ есть зеркала (JetBrains Runtime 17, зеркала Adoptium) |
| **Android Studio** | ~1.1 ГБ | developer.android.com/studio; в РФ доступно зеркало у JetBrains |
| **SDK Platform 35** | ~60 МБ | через SDK Manager внутри Studio |
| **Build-Tools 34.0.0** | ~55 МБ | через SDK Manager |
| **NDK 27.2.12479018** | **620 МБ** | SDK Manager → SDK Tools → NDK (Side by side) → Show Package Details. Прямая ссылка: `https://dl.google.com/android/repository/android-ndk-r27b-linux.zip` (r27b = 27.2.12479018) |
| AGP 8.7.3 + androidx | ~300 МБ | качает сам Gradle при первом sync с `dl.google.com` |

`dl.google.com` и `developer.android.com` из РФ обычно работают (в отличие от
GitHub), так что основной риск — это объём, а не блокировка. Скачивайте
по одному файлу и с докачкой (`wget -c`), а не всё сразу.

Если `dl.google.com` у вас не открывается — напишите, соберу офлайн-набор
SDK-компонентов (у меня в песочнице уже есть `android.jar` API 35 и 47
androidx-артефактов; они лежат в `aar/` этого набора).

---

## Порядок сборки

```bash
# 0. распаковать bundle-with-native.zip, зайти в папку
cd bundle

# 1. настроить зеркало Go-модулей (один раз)
go env -w GOPROXY='https://goproxy.cn,direct'

# 2. указать JDK и NDK
export JAVA_HOME=/usr/lib/jvm/temurin-17        # ваш путь
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018

# 3. собрать AAR (10–25 минут, ~8 ГБ RAM)
./tools/build-libbox-aar.sh

# 4. проверить, что в AAR обе архитектуры
unzip -l android/app/libs/flicker-box.aar | grep 'jni/.*libflickerbox\.so'
#    jni/arm64-v8a/libflickerbox.so
#    jni/x86_64/libflickerbox.so

# 5. открыть android/ в Android Studio → Build → Build APK(s)
```

Результат: `android/app/build/outputs/apk/debug/app-debug.apk`.

---

## Если Gradle лезет качать дистрибутив и не может

В наборе есть `gradle-8.9-bin.zip` (129 МБ) — ровно та версия, что прописана в
`android/gradle/wrapper/gradle-wrapper.properties`. Положите его туда, куда
wrapper ожидает, и качать ничего не придётся:

```bash
D=$HOME/.gradle/wrapper/dists/gradle-8.9-bin
mkdir -p "$D/tmp"
cp gradle-8.9-bin.zip "$D/tmp/"
cd "$D/tmp" && unzip -q ../gradle-8.9-bin.zip && cd ..
# wrapper ищет каталог вида <hash>/gradle-8.9; проще всего дать ему локальный путь:
```

Либо просто поправьте `android/gradle/wrapper/gradle-wrapper.properties`:

```properties
distributionUrl=file\:/ABSOLUTE/PATH/TO/gradle-8.9-bin.zip
```

(путь обязательно абсолютный, `file\:` с экранированным двоеточием).

Третий вариант — не использовать wrapper вообще: распакуйте `gradle-8.9-bin.zip`
и запускайте `<путь>/gradle-8.9/bin/gradle :app:assembleDebug` из папки `android/`.

---

## Что в этом наборе

| Файл | Зачем |
|---|---|
| `check-env.sh` | диагностика: что установлено, что доступно, какое зеркало быстрее |
| `README-OFFLINE.md` | этот файл |
| `gradle-8.9-bin.zip` | дистрибутив Gradle — чтобы wrapper его не качал (129 МБ) |
| `kotlin-compiler-1.9.24.zip` | kotlinc той же версии, что в проекте. **Для сборки APK не нужен** — Gradle возьмёт свой. Пригодится, если захотите проверить компиляцию Kotlin без Android Studio |
| `aar/` | 47 androidx/material/coroutines-артефактов. **В этот архив не вошли** (см. ниже) |

### Честно про «полностью офлайн»

Полностью офлайновую сборку Gradle этот набор **не обеспечивает**. Даже если
разложить androidx-артефакты в локальный maven-репозиторий, Gradle всё равно
потребует сам **AGP 8.7.3** и **Kotlin Gradle Plugin 1.9.24** вместе с их
транзитивными зависимостями — это ещё несколько сотен МБ с `dl.google.com`,
`repo1.maven.org` и `plugins.gradle.org`.

Реалистичный расклад такой:

- **Go-часть (сборка AAR)** делается офлайн почти полностью — достаточно
  `GOPROXY` на доступное зеркало или уже наполненного `~/go/pkg/mod`. Это
  самый тяжёлый кусок (2.6–3.8 ГБ), и он решён.
- **Gradle-часть (сборка APK)** требует одного сеанса с интернетом на первый sync:
  ~300–500 МБ с `dl.google.com`. После первого sync всё оседает в
  `~/.gradle/caches` и дальше собирается офлайн.

Если `dl.google.com` у вас принципиально недоступен — напишите, тогда есть два
варианта: (а) собрать APK здесь, в песочнице, если я смогу поставить Android
SDK (мешает нехватка диска: нужно ~8 ГБ, свободно ~1.7 ГБ), или (б) подготовить
полный офлайн-maven-репозиторий нужных артефактов — но его тоже придётся
скачать, просто один раз и с зеркала.

**Офлайн-набор Go-модулей в этот архив не вошёл** — он весит 3.8 ГБ
(~1.2 ГБ в tar.gz), что при вашем интернете бессмысленно, и почти наверняка
уже есть у вас в `~/go/pkg/mod`. Если `check-env.sh` покажет, что кэша нет и
зеркала не работают — скажите, соберу и отдам отдельно.

---

## Чего делать НЕ нужно

- **Не нужен GitHub**: ни форк, ни push, ни CI. Всё собирается локально.
- **Не нужен `git`** вообще — достаточно распакованной папки.
- **Не ставьте CMake** — в проекте нет `externalNativeBuild`, нативное ядро
  собирается через gomobile, не через Gradle.
- **Не меняйте набор build-тегов** в `tools/build-libbox-aar.sh` без нужды:
  без `with_utls` молча исчезнет Reality/uTLS, без `with_gvisor` — userspace-сеть.
