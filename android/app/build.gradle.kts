// SPDX-License-Identifier: GPL-3.0-or-later
import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// ---------------------------------------------------------------------------
//  Версия — из version.properties в корне android/, чтобы versionCode рос сам
//  и не расходился с тем, что уехало в релиз. Если файла нет — фолбэк.
// ---------------------------------------------------------------------------
fun versionProp(key: String, fallback: String): String {
    val f = rootProject.file("version.properties")
    if (f.exists()) {
        val p = Properties().apply { FileInputStream(f).use { load(it) } }
        p.getProperty(key)?.takeIf { it.isNotBlank() }?.let { return it }
    }
    return fallback
}

// ---------------------------------------------------------------------------
//  Подпись. Порядок поиска: переменные окружения → gradle.properties →
//  local.properties. НИЧЕГО из этого не коммитится (local.properties в .gitignore).
//
//  ПОЧЕМУ ЭТО ВАЖНО И ЧТО БЫЛО СЛОМАНО
//  -----------------------------------
//  Было:
//      signingConfigs { /* пусто, только комментарий */ }
//      buildTypes { release { signingConfig = signingConfigs.getByName("debug") } }
//
//  Release подписывался debug-ключом. Само по себе это ещё не смертельно —
//  AGP всё равно зовёт apksigner со схемами v1+v2. Смертельно то, что из-за
//  debug-ключа релизную сборку нельзя было раздать как «настоящую», и APK
//  ушёл на доводку руками: его распаковали, что-то поправили («FIXED3»),
//  запаковали обратно zip-архиватором и подписали jarsigner'ом с самодельным
//  ключом «CN=FlickerVPN local patch 2».
//
//  jarsigner умеет ТОЛЬКО v1 (JAR signing). Он не создаёт APK Signing Block,
//  то есть v2/v3 в файле не появляется вовсе. При targetSdk = 35 Android 11+
//  такой пакет не принимает:
//      ERROR: Target SDK version 35 requires a minimum of signature scheme v2
//
//  Отсюда «ставится, но не запускается»: часть оболочек показывает прогресс
//  установки и молча откатывает пакет, а иконка остаётся от прошлой сборки.
//
//  Плюс ручная перепаковка сделала ещё две вещи:
//    * пережала libflickerbox.so в DEFLATE, хотя useLegacyPackaging = false
//      требует хранить .so НЕСЖАТОЙ и выровненной → пришлось править манифест
//      на extractNativeLibs="true";
//    * подменила foregroundServiceType="vpn" на "specialUse" и потеряла
//      разрешение FOREGROUND_SERVICE_VPN.
//
//  ВЫВОД: APK нельзя доделывать руками. Всё, что нужно, делает Gradle.
// ---------------------------------------------------------------------------
fun secret(key: String): String =
    System.getenv(key)
        ?: (project.findProperty(key) as? String)
        ?: run {
            val lp = rootProject.file("local.properties")
            if (lp.exists()) Properties().apply { FileInputStream(lp).use { load(it) } }.getProperty(key) else null
        }
        ?: ""

// ---------------------------------------------------------------------------
//  Где лежит ядро. Определяется ДО блока android {}, потому что от этого
//  зависит ndk.abiFilters (какие ABI вообще есть смысл упаковывать).
//  Пояснения и история — перед блоком dependencies {} ниже.
// ---------------------------------------------------------------------------
val coreAar = file("libs/flicker-box.aar")
val coreJar = file("libs/flicker-core.jar")
val coreSoFiles: List<File> = file("src/main/jniLibs").let { dir ->
    if (dir.exists()) {
        dir.walkTopDown().filter { it.isFile && it.name == "libflickerbox.so" }.toList()
    } else {
        emptyList<File>()
    }
}

android {
    namespace = "dev.flicker.vpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.flicker.vpn"
        minSdk = 24
        targetSdk = 35
        versionCode = versionProp("VERSION_CODE", "401").toInt()
        versionName = versionProp("VERSION_NAME", "4.0.1")

        // Версия NDK зафиксирована явно и совпадает в трёх местах:
        //   android/app/build.gradle.kts (здесь), tools/build-libbox-aar.sh,
        //   .github/workflows/android.yml.
        // 27.2.12479018 — это NDK из CI; дефолт AGP 8.7 — 27.0.12077973.
        ndkVersion = "27.2.12479018"

        // ABI.
        //
        // БЫЛО: listOf("arm64-v8a", "x86_64") — то есть 32-битные устройства
        // (armeabi-v7a) не покрыты вовсе. На них в APK нет ни одной .so,
        // System.loadLibrary("flickerbox") кидает UnsatisfiedLinkError, и
        // (до правки FlickerApp) приложение умирало прямо в Application.onCreate.
        //
        // x86_64 оставлен — он нужен для эмулятора Android Studio.
        //
        // ВАЖНО: abiFilters только ФИЛЬТРУЕТ то, что лежит в AAR. Если
        // tools/build-libbox-aar.sh собран с -target android/arm64,android/amd64,
        // то armeabi-v7a здесь взяться неоткуда. Чтобы покрыть 32-битные
        // устройства, в скрипте надо добавить android/arm:
        //     TARGETS="android/arm64,android/arm,android/amd64"
        // и только потом расширять этот список. Иначе получите APK, который
        // ставится на armeabi-v7a и падает при старте — ровно тот баг, что чиним.
        ndk {
            // ИЗМЕРЕНО: в наличии ровно одна ABI.
            //
            //   tools/extract-core.py достаёт libflickerbox.so из
            //   FlickerVPN-4_0_3-arm64-FIXED3.apk, а там лежит только
            //   lib/arm64-v8a/ — ни armeabi-v7a, ни x86_64, ни x86.
            //
            // Прежний список из четырёх ABI был взят из tools/build-libbox-aar.sh
            // (TARGETS=arm64,arm,amd64,386) и описывал НЕ фактическое
            // содержимое, а намерение. abiFilters только фильтрует то, что уже
            // есть; несуществующие ABI он не создаёт. Опасность в том, что
            // широкий список выглядит как «поддержка всех устройств», хотя APK
            // получается arm64-единственным — и на 32-битном телефоне падает с
            // UnsatisfiedLinkError, ничем себя не выдав на этапе сборки.
            //
            // Поэтому список выводится из того, что РЕАЛЬНО лежит на диске:
            //   * AAR (сборка из Go)  -> берём пересечение с его содержимым;
            //   * jniLibs (восстановленное ядро) -> ровно найденные каталоги.
            // Пустой abiFilters означает «не фильтровать», так что ядро из AAR
            // со всеми четырьмя ABI пройдёт насквозь без потерь.
            val abiFromDisk: Set<String> = when {
                coreSoFiles.isNotEmpty() ->
                    coreSoFiles.map { it.parentFile.name }.toSet()
                coreAar.exists() ->
                    // AAR ещё не распакован на этапе конфигурации; фильтр
                    // оставляем пустым — Gradle возьмёт из AAR всё, что там есть,
                    // а tools/build-libbox-aar.sh сам печатает список ABI.
                    emptySet()
                else -> emptySet()
            }
            if (abiFromDisk.isNotEmpty()) {
                abiFilters += abiFromDisk
                logger.lifecycle("[core] ABI в пакете: ${abiFromDisk.sorted().joinToString(", ")}")
            } else {
                logger.lifecycle("[core] abiFilters не задан — беру из ядра всё, что там есть")
            }
        }
    }

    // -----------------------------------------------------------------------
    //  v4.7.0: нативная сборка byedpi (обход DPI).
    //
    //  С этого момента NDK и CMake СТАНОВЯТСЯ ОБЯЗАТЕЛЬНЫМИ. Раньше проект
    //  собирался без них: ядро libflickerbox.so приходит готовым бинарником,
    //  а keepDebugSymbols (см. packaging.jniLibs ниже) отключал NDK-стриппер.
    //  Теперь появился второй нативный компонент, который компилируется из C:
    //
    //      app/src/main/cpp/byedpi/  — исходники hufrea/byedpi 17.3, ДОСЛОВНО
    //                                  из submodule EwenLoy/ByeByeDPI-x-tg
    //                                  v1.0.1-build5 (commit e0fccf68bf74046d0e5b614850d7973c41ec19db)
    //      app/src/main/cpp/native-lib.c, main.h — JNI-обёртка эталона
    //                                  (переименованы только JNI-символы под dev.flicker.vpn.core)
    //      app/src/main/cpp/CMakeLists.txt
    //
    //  v4.12.0: второй нативный компонент обхода DPI — tun2socks
    //  hev-socks5-tunnel (app/src/main/jni/, задача runNdkBuild ниже).
    //  Оба вместе воспроизводят рабочую схему эталона:
    //  TUN → hev-socks5-tunnel → SOCKS5 127.0.0.1:1080 (byedpi) → интернет.
    //
    //  Ставится в Android Studio → Settings → Languages & Frameworks →
    //  Android SDK → SDK Tools → галочки «NDK (Side by side)» и «CMake».
    //  Версия NDK уже зафиксирована выше: 27.2.12479018.
    //
    //  ABI: externalNativeBuild собирает ровно те ABI, что в ndk.abiFilters,
    //  то есть arm64-v8a (выводится из содержимого jniLibs). libbyedpi.so
    //  получается ~60-120 КБ — на размер APK это не влияет заметно.
    // -----------------------------------------------------------------------
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // -----------------------------------------------------------------------
    //  v4.10.0: Telegram-туннель — предсобранная Rust-библиотека
    //  libtgwsproxy.so (MTProto-WS-прокси, форк Flowseal/tg-ws-proxy; тот же
    //  бинарник, что кладёт в свой APK EwenLoy/ByeByeDPI-x-tg).
    //
    //  Файлы: src/main/tglibs/{arm64-v8a,armeabi-v7a}/libtgwsproxy.so
    //         (2 096 432 и 1 365 312 байт).
    //
    //  ПОЧЕМУ ОТДЕЛЬНАЯ ПАПКА, А НЕ src/main/jniLibs.
    //  Gradle/AGP считает каталог jniLibs «своим»: задачи strip*DebugSymbols и
    //  merge*JniLibFolders пишут туда же и могут вычистить чужие .so. Плюс
    //  abiFromDisk выше выводится ИМЕННО из jniLibs по наличию
    //  libflickerbox.so — если положить туда ещё и tglibs, логика вывода ABI
    //  начнёт учитывать посторонние файлы. Отдельный srcDir этого избегает.
    //  Та же схема в ByeByeDPI-x-tg (у них tglibs рядом с jniLibs).
    //
    //  ЧТО С armeabi-v7a.
    //  v7a-библиотека лежит здесь на будущее, но в APK она НЕ ПОПАДЁТ:
    //  abiFilters (см. выше) выводится из фактического наличия
    //  libflickerbox.so, а та есть только под arm64-v8a. Так и задумано —
    //  на 32-битном устройстве приложение всё равно не запустится без ядра,
    //  а добавление "armeabi-v7a" в abiFilters дало бы APK, который ставится
    //  и падает на System.loadLibrary("flickerbox"). Не «расширять список ABI»
    //  до тех пор, пока ядро не пересобрано под android/arm.
    // -----------------------------------------------------------------------
    sourceSets {
        getByName("main") {
            // v4.12.0: hevlibs — вывод задачи runNdkBuild (libhev-socks5-tunnel.so,
            // tun2socks для обхода DPI — порт из ByeByeDPI-x-tg). Отдельная папка
            // ОБЯЗАТЕЛЬНА по двум причинам (обе из эталона):
            //   1. ndk-build с NDK_LIBS_OUT чистит выходной каталог и удаляет
            //      чужие .so — в src/main/jniLibs лежит libflickerbox.so (ядро);
            //   2. abiFromDisk выводится из jniLibs по наличию libflickerbox.so,
            //      посторонние файлы там ломают логику вывода ABI.
            jniLibs.srcDirs("src/main/jniLibs", "src/main/tglibs", "src/main/hevlibs")
        }
    }

    signingConfigs {
        // Release-ключ. Создаётся только если он реально задан — иначе сборка
        // честно упадёт с сообщением, а не соберёт APK, подписанный debug-ключом.
        create("release") {
            val path = secret("FLICKER_KEYSTORE_FILE")
            if (path.isNotEmpty()) {
                storeFile = file(path)
                storePassword = secret("FLICKER_KEYSTORE_PASSWORD")
                keyAlias = secret("FLICKER_KEY_ALIAS")
                keyPassword = secret("FLICKER_KEY_PASSWORD")
            }
        }
        // Debug-ключ оставляем как есть — для assembleDebug.
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            // gomobile JNI: не урезать без аккуратных keep-правил.
            // Правила в proguard-rules.pro уже есть и корректны — minify можно
            // включить, но ТОЛЬКО после проверки seeds.txt (см. BUILD-ANDROID.md).
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")

            // Явно false. Раньше атрибут не задавался, и в «доведённом руками»
            // APK в манифесте оказался android:debuggable="true".
            isDebuggable = false
            isJniDebuggable = false

            // БЫЛО: signingConfig = signingConfigs.getByName("debug")  ← корень проблемы
            val releaseConfig = signingConfigs.getByName("release")
            if (releaseConfig.storeFile != null) {
                signingConfig = releaseConfig
            } else {
                // Не даём собрать «релиз» debug-ключом по умолчанию.
                // Падаем внятно, с инструкцией, а не выпускаем APK,
                // который потом не установится на устройство пользователя.
                throw GradleException(
                    """
                    |Не задан релизный ключ подписи.
                    |
                    |Создайте keystore:
                    |  keytool -genkeypair -v -keystore ~/keys/flicker-release.jks \
                    |    -storetype PKCS12 -keyalg RSA -keysize 4096 -validity 10950 \
                    |    -alias flicker -dname "CN=FlickerVPN, OU=Mobile, O=Flicker, C=RU"
                    |
                    |И пропишите в android/local.properties (файл в .gitignore):
                    |  FLICKER_KEYSTORE_FILE=/абсолютный/путь/flicker-release.jks
                    |  FLICKER_KEYSTORE_PASSWORD=...
                    |  FLICKER_KEY_ALIAS=flicker
                    |  FLICKER_KEY_PASSWORD=...
                    |
                    |Для отладочной сборки используйте ./gradlew assembleDebug.
                    """.trimMargin()
                )
            }
            vcsInfo.include = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
        // ОБЯЗАТЕЛЬНО: с AGP 8.0 класс BuildConfig НЕ генерируется по умолчанию.
        buildConfig = true
    }

    // -----------------------------------------------------------------------
    //  ABI-сплиты: четыре отдельных APK + один universal.
    //  Так же устроен релиз ByeByeDPI-x-tg (app-arm64-v8a-release.apk … +
    //  app-universal-release.apk) и sing-box-for-android.
    //
    //  universalApk = true обязателен, если раздаёшь одну ссылку «для всех».
    //  Он содержит .so под все ABI, поэтому заметно тяжелее — но ставится везде.
    //
    //  Включать ТОЛЬКО после того, как AAR пересобран под все четыре цели.
    // -----------------------------------------------------------------------
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
            isUniversalApk = true
        }
    }

    packaging {
        jniLibs {
            // -----------------------------------------------------------------
            // СПРАВКА: что означают оба значения. ДЕЙСТВУЮЩЕЕ — true, оно
            // выставлено ниже по результату измерения выравнивания реальной
            // libflickerbox.so. Этот блок оставлен как объяснение, а не как
            // текущая конфигурация.
            // -----------------------------------------------------------------
            // useLegacyPackaging = false  →  android:extractNativeLibs="false":
            // .so хранится в APK НЕСЖАТОЙ и маппится в память прямо оттуда.
            // Быстрее старт, не дублируется 64 МБ на диске.
            //
            // ЦЕНА: несжатая .so обязана быть выровнена по границе страницы,
            // а на Android 15+ с 16-килобайтной страницей — по 16 КБ. Если
            // gomobile соберёт .so без 16KB-выравнивания, dlopen упадёт на
            // таких устройствах, и приложение не запустится.
            //
            // ПРОВЕРИТЬ после сборки AAR:
            //   unzip -o app/libs/flicker-box.aar -d /tmp/aar
            //   readelf -l /tmp/aar/jni/arm64-v8a/libflickerbox.so | grep LOAD
            //   →Align у LOAD-сегментов должен быть 0x4000 (16 КБ), не 0x1000.
            //
            // Если Align = 0x1000, а поддерживать Android 15 / 16KB-устройства
            // нужно — временно поставьте true. Тогда .so распаковывается на диск
            // (медленнее старт, +64 МБ), но выравнивание не важно.
            //
            // Ручная перепаковка APK это setting ЛОМАЕТ: zip-архиватор сожмёт
            // .so обратно, и она не загрузится. Ещё одна причина не трогать
            // готовый APK руками.
            // -----------------------------------------------------------------
            // ИЗМЕРЕНО, А НЕ ПРЕДПОЛОЖENO. Разобран libflickerbox.so из
            // рабочего APK FlickerVPN-4_0_3-arm64-FIXED3 (64 744 288 байт,
            // ELF64, DYN/shared), прочитаны program-заголовки:
            //
            //   PT_LOAD  offset=0          vaddr=0x0        align=0x1000
            //   PT_LOAD  offset=32333952   vaddr=0x1ed7080  align=0x1000
            //   PT_LOAD  offset=55588192   vaddr=0x3505560  align=0x1000
            //   PT_LOAD  offset=63740160   vaddr=0x3ccc900  align=0x1000
            //
            // Align = 0x1000 (4 КБ), НЕ 0x4000 (16 КБ).
            //
            // При useLegacyPackaging = false (extractNativeLibs="false") .so
            // хранится в APK несжатой и маппится в память прямо оттуда, поэтому
            // обязана быть выровнена по границе страницы. На Android 15+ с
            // 16-килобайтной страницей dlopen такой библиотеки ПАДАЕТ, и
            // приложение не стартует вовсе — без единой строчки в Java-логе.
            //
            // Значит, для ЭТОЙ .so единственно верное значение — true: .so
            // сжимается и распаковывается на диск, выравнивание не важно.
            //
            // ЦЕНА true: старт чуть медленнее и +62 МБ на диске после установки
            // (библиотека существует в двух копиях: в APK и в /data/app/.../lib).
            // Это приемлемо; неприемлемо — не запускающееся приложение.
            //
            // Вернуть false можно ТОЛЬКО после пересборки AAR с 16-килобайтным
            // выравниванием. В tools/build-libbox-aar.sh для этого добавить в
            // gomobile bind:
            //     -ldflags "-s -w -extldflags=-Wl,-z,max-page-size=16384"
            // и обязательно проверить результат:
            //     readelf -lW libflickerbox.so | awk '/LOAD/{print $NF}'
            //     → должно быть 0x4000 у всех LOAD-сегментов.
            // Пока такой проверки нет — не трогать.
            // -----------------------------------------------------------------
            useLegacyPackaging = true

            // НЕ ЗАПУСКАТЬ stripDebugSymbols над нашей .so.
            //
            // Зачем это здесь. По умолчанию AGP прогоняет каждую .so из
            // jniLibs через NDK-стриппер (задача strip<Abi>DebugSymbols).
            // Следствия, которые нам не нужны:
            //   1. Требует установленный NDK ровно версии ndkVersion
            //      (27.2.12479018). Без него сборка падает ещё до компиляции —
            //      а NDK это ~1 ГБ отдельной установки.
            //      ОБНОВЛЕНИЕ v4.7.0: NDK теперь всё равно нужен — им
            //      собирается libbyedpi.so через externalNativeBuild (см. выше).
            //      Но стриппать 64-мегабайтную libflickerbox.so по-прежнему
            //      незачем и вредно, поэтому keepDebugSymbols остаётся.
            //   2. Стрипать нечего: .so собрана gomobile с -ldflags "-s -w",
            //      то есть без отладочных символов. Проверено на донорском
            //      файле — 64 744 288 байт, секций .debug_* нет.
            //   3. Лишнее переписывание 62-мегабайтного бинарника — риск
            //      испортить то, что заведомо работало на этом телефоне.
            //
            // keepDebugSymbols отключает стриппер для указанных путей, и NDK
            // больше не требуется. Если позже понадобится именно стрип —
            // ставьте NDK 27.2.12479018 и убирайте эту строку.
            keepDebugSymbols += "**/libflickerbox.so"
            // v4.10.0: то же для Rust-библиотеки Telegram-туннеля. Стриппер ей
            // не нужен (она собрана релизным профилем, отладочных секций почти
            // нет), а вот риск есть: NDK-стрип чужого cdylib с Rust-unwind
            // таблицами — лишняя переменная в сборке, которую нельзя проверить
            // на месте. Дешевле не трогать. libjnidispatch.so из JNA стриппается
            // штатно, его не исключаем.
            keepDebugSymbols += "**/libtgwsproxy.so"
        }
        resources {
            excludes += setOf("META-INF/DEPENDENCIES", "META-INF/LICENSE*", "META-INF/NOTICE*")
        }
    }

    testOptions {
        // android.util.Log в unit-тестах не мокается, а возвращает значения
        // по умолчанию. Без этого Resilience не протестировать без Robolectric,
        // а он для чистой логики избыточен.
        unitTests.isReturnDefaultValues = true
    }

    lint {
        // Ловим вызовы API новее minSdk на этапе сборки, а не крашем у пользователя.
        fatal += "NewApi"
        abortOnError = true
        checkReleaseBuilds = true
    }

    // metadata-блок Google Play — не нужен и мешает F-Droid/IzzyOnDroid
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    // Читаемые имена: FlickerVPN-4.0.4-arm64-v8a.apk вместо app-arm64-v8a-release.apk
    applicationVariants.configureEach {
        outputs.configureEach {
            val out = this as com.android.build.gradle.internal.api.BaseVariantOutputImpl
            out.outputFileName = out.outputFileName
                .replace("app-", "FlickerVPN-${versionName}-")
                .replace("-release", "")
                .replace("-universal", "-universal")
        }
    }
}

// ---------------------------------------------------------------------------
//  ЯДРО (libbox + mobile-фасад). ГЛАВНАЯ ПРАВКА СБОРКИ.
//
//  БЫЛО:
//      dependencies { implementation(files("libs/flicker-box.aar")) }
//
//  `files(...)` в Gradle — ЛЕНИВАЯ файловая коллекция. Если файла по пути нет,
//  он просто игнорируется: ни ошибки конфигурации, ни ошибки компиляции
//  (Kotlin-код обращается к dev.flicker.libbox.* по полному имени, и пока AAR
//  на месте — всё честно; когда AAR нет, сборка должна падать, но не падала,
//  потому что классы ядра подставлялись заглушками/обходились).
//
//  ИТОГ: собирался APK ~5 МБ вместо ~25 МБ — БЕЗ libflickerbox.so. Он
//  устанавливался, запускался и умирал на первом же обращении к туннелю:
//      System.loadLibrary("flickerbox") -> UnsatisfiedLinkError
//  что выглядит ровно как «приложение молча закрывается при подключении».
//
//  Для справки, из чего состоят 25.14 МБ рабочего APK:
//      lib/arm64-v8a/libflickerbox.so   61.74 МБ -> 19.57 МБ в zip   78%
//      classes.dex                       9.94 МБ ->  3.70 МБ         15%
//      resources.arsc                    1.02 МБ ->  1.02 МБ (STORED) 4%
//      всё остальное (855 res, dex2-4, META-INF)                     ~3%
//  То есть движок — это четыре пятых приложения. APK весом 3-6 МБ рабочим
//  быть НЕ МОЖЕТ в принципе.
//
//  ТЕПЕРЬ отсутствие ядра — ошибка сборки с внятным текстом, а не тихий брак.
//
//  Поддерживаются два источника, по приоритету:
//    1. libs/flicker-box.aar   — честная сборка из Go-исходников
//                                (tools/build-libbox-aar.sh: Go 1.26, NDK
//                                27.2.12479018, JDK 17, ~16 ГБ, 30-50 мин).
//    2. libs/flicker-core.jar  — классы ядра, восстановленные из РАБОЧЕГО APK
//                                (tools/make-core-jar.py), плюс сама
//                                libflickerbox.so в src/main/jniLibs/<abi>/
//                                (tools/extract-core.py).
//       Вариант 2 не требует Go-тулчейна вообще. JNI-сигнатуры и классы берутся
//       из одного и того же APK, поэтому совпадают по построению: в .so
//       экспортируется 1285 символов Java_dev_flicker_* и 6 символов
//       Java_go_Seq_*/Java_go_Universe_*, и ровно эти пакеты попадают в jar.
// ---------------------------------------------------------------------------
fun coreMissing(what: String): Nothing = throw GradleException(
    """
    |
    |НЕ НАЙДЕНО ЯДРО ПРИЛОЖЕНИЯ: $what
    |
    |Без libflickerbox.so APK соберётся, установится и УМРЁТ при первом
    |подключении (UnsatisfiedLinkError). Собирать такой пакет бессмысленно,
    |поэтому сборка прервана.
    |
    |Вариант A — восстановить ядро из рабочего APK (быстро, без Go):
    |    python3 tools/extract-core.py
    |    # затем на машине с Java: dex2jar classes.dex и
    |    python3 tools/make-core-jar.py <путь>/classes-dex2jar.jar
    |
    |Вариант B — собрать ядро из Go-исходников (чисто, долго):
    |    ./tools/build-libbox-aar.sh
    |
    |Подробно: BUILD-NOW.md
    |
    """.trimMargin()
)

when {
    coreAar.exists() ->
        logger.lifecycle("[core] ядро: ${coreAar.name} (${coreAar.length() / 1024 / 1024} МБ)")

    coreJar.exists() -> {
        if (coreSoFiles.isEmpty()) coreMissing("есть libs/flicker-core.jar, но нет ни одной libflickerbox.so в app/src/main/jniLibs/")
        logger.lifecycle(
            "[core] ядро: ${coreJar.name} (${coreJar.length() / 1024} КБ) + " +
                coreSoFiles.joinToString(", ") { it.parentFile.name + "/libflickerbox.so (" + it.length() / 1024 / 1024 + " МБ)" }
        )
    }

    coreSoFiles.isNotEmpty() ->
        coreMissing("есть libflickerbox.so, но нет ни libs/flicker-box.aar, ни libs/flicker-core.jar — компиляция не пройдёт (unresolved reference: dev.flicker.libbox)")

    else ->
        coreMissing("нет ни libs/flicker-box.aar, ни libs/flicker-core.jar, ни .so в jniLibs")
}

// ---------------------------------------------------------------------------
//  v4.10.0: проверка наличия libtgwsproxy.so.
//
//  В ОТЛИЧИЕ от ядра здесь НЕ падаем. Причины:
//   * Telegram-туннель — дополнительная функция, без неё VPN и обход DPI
//     работают как работали. Ронять из-за неё всю сборку неправильно;
//   * TgWsActivity проверяет наличие файла в рантайме и показывает плашку
//     «библиотека не найдена», а TgWsService сообщает то же текстом ошибки.
//     То есть молчаливого «нажал — ничего не произошло» не будет.
//  Пишем заметное предупреждение, чтобы пропажу было видно в выводе Gradle.
// ---------------------------------------------------------------------------
val tgLibs = file("src/main/tglibs")
val tgSoFiles: List<File> = if (tgLibs.exists()) {
    tgLibs.walkTopDown().filter { it.isFile && it.name == "libtgwsproxy.so" }.toList()
} else {
    emptyList()
}
if (tgSoFiles.isEmpty()) {
    logger.warn(
        "[tgws] ВНИМАНИЕ: не найдено ни одной libtgwsproxy.so в app/src/main/tglibs/. " +
            "Telegram-туннель в этой сборке работать не будет (экран покажет плашку). " +
            "Файлы берутся из релиза EwenLoy/ByeByeDPI-x-tg."
    )
} else {
    logger.lifecycle(
        "[tgws] Telegram-туннель: " + tgSoFiles.joinToString(", ") {
            it.parentFile.name + "/libtgwsproxy.so (" + it.length() / 1024 + " КБ)"
        }
    )
}

dependencies {
    // Ядро: libbox (sing-box) + mobile-фасад FLICKER. Один из двух источников,
    // проверка и пояснения — сразу над этим блоком.
    if (coreAar.exists()) {
        implementation(files(coreAar))
    } else {
        implementation(files(coreJar))
    }

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // -----------------------------------------------------------------------
    //  v4.10.0: JNA — вызовы Rust-библиотеки libtgwsproxy.so (Telegram-туннель).
    //
    //  ПОЧЕМУ ИМЕННО `@aar`, А НЕ ОБЫЧНАЯ ЗАВИСИМОСТЬ.
    //  net.java.dev.jna:jna публикует на Maven Central ДВА артефакта одной
    //  версии: jna-5.14.0.jar (десктоп) и jna-5.14.0.aar (Android). В jar нет
    //  libjnidispatch.so — а это нативный мост JNA, без него любой вызов
    //  падает с UnsatisfiedLinkError уже на Native.load(). Суффикс `@aar`
    //  жёстко выбирает Android-сборку, внутри которой лежат
    //  jni/{arm64-v8a,armeabi-v7a,x86,x86_64}/libjnidispatch.so.
    //  Ровно так же подключено в EwenLoy/ByeByeDPI-x-tg.
    //
    //  `@aar` отключает разбор transitives — для JNA это не важно:
    //  у неё нет обязательных зависимостей.
    //
    //  РАЗМЕР: ~506 КБ в AAR, из них classes.jar ~450 КБ. В APK под arm64
    //  уходит примерно 300 КБ классов + ~90 КБ libjnidispatch.so.
    // -----------------------------------------------------------------------
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Нужны для перенесённых компонентов (QuickTileService, BootReceiver,
    // Battery, экран настроек). См. docs/03-PORT-BYEBYEDPI.md.
    implementation("androidx.activity:activity-ktx:1.8.0")
    implementation("androidx.lifecycle:lifecycle-service:2.8.7")
    implementation("androidx.preference:preference-ktx:1.2.1")

    testImplementation("junit:junit:4.13.2")
    // РЕАЛЬНАЯ реализация org.json для unit-тестов.
    // Без неё org.json берётся из android.jar, где все методы — заглушки,
    // возвращающие дефолты (при isReturnDefaultValues = true). То есть
    // JSONObject().put(...) ничего не сохранит, и ConfigMigrateTest
    // пройдёт «зелёным», не проверив ровным счётом ничего.
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}

// ---------------------------------------------------------------------------
//  v4.12.0: сборка libhev-socks5-tunnel.so (tun2socks) через ndk-build.
//
//  Порт задачи runNdkBuild из EwenLoy/ByeByeDPI-x-tg (app/build.gradle.kts).
//  Исходники: src/main/jni/hev-socks5-tunnel (submodule-дерево эталона:
//  hev-socks5-core, hev-task-system, lwip, yaml). Application.mk задаёт
//  PKGNAME=dev/flicker/vpn/core — по нему JNI_OnLoad (src/hev-jni.c) находит
//  класс dev.flicker.vpn.core.TProxyService для RegisterNatives.
//
//  NDK_LIBS_OUT — src/main/hevlibs (НЕ jniLibs): ndk-build чистит выходной
//  каталог, а в jniLibs лежит libflickerbox.so. См. комментарий в sourceSets.
// ---------------------------------------------------------------------------
tasks.register<Exec>("runNdkBuild") {
    group = "build"
    description = "Собрать libhev-socks5-tunnel.so (tun2socks обхода DPI) через ndk-build"

    val ndkDir = android.ndkDirectory
    executable = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
        "$ndkDir\\ndk-build.cmd"
    } else {
        "$ndkDir/ndk-build"
    }
    setArgs(listOf(
        "NDK_PROJECT_PATH=build/intermediates/ndkBuild",
        "NDK_LIBS_OUT=src/main/hevlibs",
        "APP_BUILD_SCRIPT=src/main/jni/Android.mk",
        "NDK_APPLICATION_MK=src/main/jni/Application.mk"
    ))
}

tasks.preBuild {
    dependsOn("runNdkBuild")
}
