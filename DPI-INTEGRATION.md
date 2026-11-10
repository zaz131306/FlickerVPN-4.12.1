# v4.12.0 — Обход DPI: полный порт рабочей схемы из ByeByeDPI-x-tg

Этот документ описывает, ЧТО именно перенесено из
[EwenLoy/ByeByeDPI-x-tg v1.0.1-build5](https://github.com/EwenLoy/ByeByeDPI-x-tg/releases/tag/v1.0.1-build5)
(приложение, в котором обход DPI у пользователя РАБОТАЕТ) в FlickerVPN,
и какие собственные баги обхода при этом исправлены.

---

## 1. Почему обход DPI не работал в 4.11.0

Режим «Обход DPI» в 4.11.0 был устроен НЕ так, как в эталоне, и имел четыре
независимых дефекта:

1. **Чужая схема туннеля.** Вместо эталонной связки
   `TUN → tun2socks(hev-socks5-tunnel) → SOCKS5(byedpi)` использовался
   sing-box (libflickerbox.so, 64 МБ): TUN c `auto_route`, `hijack-dns`,
   DoH-детур через socks-outbound. Любой отказ парсера ядра (конфиг
   BypassConfig в формате sing-box 1.11+) или незагруженная .so — и режим
   не подключается ВООБЩЕ. Обход DPI не должен зависеть от Go-ядра.
2. **Другой commit byedpi.** Исходники в `cpp/byedpi` были с commit
   `ba532298`, а в эталоне закреплён `e0fccf68` (обе «17.3», но main.c,
   proxy.c, extend.c, params.h расходятся на сотни строк) — поведение
   на проводе могло отличаться от рабочего.
3. **Не вызывался `VpnService.prepare()`.** `MainActivity.connectBypass()`
   стартовал сервис без системного диалога согласия; на свежей установке
   `establish()` падал («проблема с подключением»). А колбэк диалога всегда
   шёл в `connectNow()`, где нужен выбранный узел — в режиме обхода его нет,
   и подтверждение молча терялось.
4. **Состояние не пересекало границу процессов.** Обход работает в процессе
   `:bypass`, UI — в основном. `Repository.setConnected`/`AppState`
   обновлялись в `:bypass`, поэтому главный экран вечно показывал
   «не подключено», горела красная плашка рассинхрона, плитка шторки
   сбрасывала статус, а смена режима не видела живой туннель.

## 2. Что перенесено из эталона (дословно)

### Нативный слой

| Файл | Источник |
|---|---|
| `android/app/src/main/cpp/byedpi/*` | submodule `hufrea/byedpi` из ByeByeDPI-x-tg, commit `e0fccf68bf74046d0e5b614850d7973c41ec19db` (17.3) — conev/desync/extend/main/mpool/packets/proxy + заголовки |
| `android/app/src/main/cpp/native-lib.c` | `cpp/native-lib.c` эталона 1:1, переименованы только JNI-символы: `Java_dev_flicker_vpn_core_ByeDpiProxy_*`. Сохранён ключевой механизм эталона `reset_params()` (clear_params + default_params: await_int=10, ipv6=1, resolve=1, udp=1, max_open=512, bfsize=16384) — повторный запуск main() в одном процессе безопасен |
| `android/app/src/main/cpp/CMakeLists.txt` | флаги эталона (`-std=c99 -O2 ... -pedantic`, `ANDROID_APP`, link `android log`) + сохранено 16K-выравнивание для Android 15+ |
| `android/app/src/main/jni/**` | `jni/` эталона: `hev-socks5-tunnel` со всеми third-part (hev-socks5-core, hev-task-system, lwip, yaml), `Android.mk`, `Application.mk`. В Application.mk изменены только `PKGNAME=dev/flicker/vpn/core` (класс TProxyService) и `APP_ABI := arm64-v8a` (ABI-покрытие Flicker) |

Сборка: задача `runNdkBuild` (порт из build.gradle.kts эталона) висит на
`preBuild.dependsOn` и кладёт `libhev-socks5-tunnel.so` в
`app/src/main/hevlibs/` (НЕ в jniLibs — ndk-build чистит выходной каталог,
а там лежит libflickerbox.so).

### Kotlin-слой

| Файл | Что |
|---|---|
| `core/TProxyService.kt` | порт `core/TProxyService.kt` эталона (JNI к tun2socks) + безопасная загрузка .so (nativeReady/loadError) |
| `core/ByeDpiProxy.kt` | JNI-обёртка byedpi; добавлен `jniForceClose()` из эталона |
| `BypassVpnService.kt` | **порт `ByeDpiVpnService` эталона**: `doStart()` (proxy → ожидание готовности SOCKS5 → TUN → tun2socks), `createBuilder()` (10.10.10.10/32, 0.0.0.0/0, DNS 8.8.8.8, setMetered(false), addDisallowedApplication(свой пакет)), `startTun2Socks()` (конфиг эталона: mtu 8500, task-stack-size 81920, socks5 127.0.0.1:1080, udp: udp), `hevCleanup()` (порядок doCleanup эталона) |
| `core/ByeDpiArgs.kt` | НЕ менялся: пресет `ref` уже был байт-в-байт командной строкой эталона. Все опции пресетов сверены с options[] перенесённого main.c — совместимы |

### Командная строка byedpi по умолчанию

Пресет `ref` (дефолт) собирает ровно то же, что эталон при своих настройках
по умолчанию (OOB, позиция 1, oob-байт '9'(0x39 — результат `-e97`),
TLS+HTTP, UDP + 1 фейк):

```
ciadpi --ip 127.0.0.1 --port 1080 -c512 -b16384 -Kt,h -o1 -e97 -An -Ku -a1 -An
```

Порт — **1080**, как в эталоне (`byedpi_proxy_port` default "1080"), а не
10888 прежней sing-box-схемы.

## 3. Что исправлено в обвязке Flicker (чтобы работало «под ключ»)

* **`MainActivity.connectBypass()`**: вместо проверки Go-ядра и валидации
  sing-box-конфига — проверка реально нужных библиотек (libbyedpi.so,
  libhev-socks5-tunnel.so) + ОБЯЗАТЕЛЬНЫЙ `VpnService.prepare()`;
  колбэк диалога согласия теперь различает обход (`pendingBypass`) и
  серверный режим.
* **Кросс-процессная синхронизация состояния**: `broadcastState()` несёт имя
  подключения (`EXTRA_NAME`); `MainActivity.stateReceiver` зеркалит
  `Repository.setConnected`/`AppState` в основной процесс — экран, плитка и
  кнопка «Отключить» видят обход так же, как VPN-режим.
* **`tunnelLive()`** в MainActivity: `TunnelService.isLive` видит только свой
  процесс, поэтому для режима обхода живой туннель определяется по наличию
  VPN-интерфейса в системе (`TunnelService.isVpnInterfaceUp`). Починены
  плашка рассинхрона, смена режима на живом туннеле, предупреждение в диалоге
  пресетов.
* **Холодный старт**: `syncBypassState()` в `onResume` восстанавливает
  «подключено», если UI перезапустился, а обход в `:bypass` жив.
* **Плитка шторки** (`QuickTileService`): статус обхода — по фактическому
  VPN-интерфейсу; старт обхода с плитки больше не требует libflickerbox.so.
* **`BootReceiver`**: автозапуск в режиме обхода не блокируется отсутствием
  Go-ядра.
* **`TunnelService`**: хук `startBypassTunnel()` (override в
  BypassVpnService = эталонный стек; базовая реализация = прежний sing-box
  путь, сохранён как запасной); `stopTunnel` переопределяется под эталонный
  teardown; инертный экземпляр (системный контрольный bind) больше не делает
  `forceTeardown` в `onDestroy` — раньше это могло убить основной процесс при
  работающем обходе.
* **`Prefs.bypassDns`** — DNS обхода (дефолт 8.8.8.8 — эталонный `dns_ip`).
* **proguard**: keep-правила `TProxyService`/`ByeDpiProxy` (JNI ищет класс по
  имени) — страховка на случай включения minify.

## 4. Итоговая схема режима «Обход DPI»

```
[приложения] → TUN (VpnService.Builder.establish(), 10.10.10.10/32, 0.0.0.0/0, DNS 8.8.8.8)
                    ↓ fd
              [hev-socks5-tunnel] (tun2socks; mtu 8500, udp: udp)
                    ↓ SOCKS5 127.0.0.1:1080
              [byedpi 17.3 e0fccf68] (JNI main(argc,argv) в процессе :bypass)
                    ↓ desync: split/OOB/fake/disorder (пресет «ref» = дефолт эталона)
              [интернет]

Собственный пакет исключён из VPN (addDisallowedApplication) — петли нет.
Sing-box в этом режиме не участвует вовсе.
```

VPN-серверы (VLESS/Trojan/HY2/…) и Telegram-туннель не тронуты — они
продолжают работать как раньше.

## 5. Сборка и проверка

1. Требования: JDK 17, NDK 27.2.12479018, CMake 3.22.1 (SDK Manager).
2. `cd android && ./gradlew :app:assembleDebug`
   (runNdkBuild и CMake запускаются сами; подробности — BUILD-ANDROID.md §1.5).
3. В APK должны лежать `lib/arm64-v8a/{libflickerbox,libbyedpi,libhev-socks5-tunnel,libtgwsproxy}.so`.
4. На устройстве: режим «Обход DPI» → «Подключить» → системный диалог согласия
   VPN (первый раз) → статус «Подключено: Обход DPI · Эталон ByeByeDPI-x-tg».
5. Проверка обхода: открыть ранее блокировавшийся сайт; при неудаче —
   «Подобрать автоматически» (перебор пресетов, работает как раньше).

## 6. Соответствие лицензиям

* byedpi — GPL-3.0 (исходники + LICENSE перенесены в `cpp/byedpi/`).
* hev-socks5-tunnel — Apache-2.0 (дерево перенесено в `jni/`, LICENSE на месте).
* FlickerVPN — GPL-3.0. Совместимо.
