# SPDX-License-Identifier: GPL-3.0-or-later
# gomobile/JNI-мосты не обрезаются: minify для release выключен в build.gradle.kts.
# Правила ниже — страховка, если minify когда-нибудь включат.
-keep class dev.flicker.libbox.** { *; }
-keep class dev.flicker.mobile.** { *; }
-keep class go.** { *; }
-keepclassmembers class * implements dev.flicker.libbox.PlatformInterface { *; }
-keepclassmembers class * implements dev.flicker.libbox.CommandServerHandler { *; }
-keepclassmembers class * implements dev.flicker.mobile.ProbeListener { *; }
-keepclassmembers class * implements dev.flicker.mobile.FetchListener { *; }
-keepclassmembers class * implements dev.flicker.mobile.SocketProtector { *; }

# ---------------------------------------------------------------------------
# ДОПОЛНЕНИЯ (нужны, если когда-нибудь включишь isMinifyEnabled = true).
# Твой базовый keep для dev.flicker.libbox/mobile/go уже корректен — ниже только
# то, что без него сломается.
# ---------------------------------------------------------------------------

# JNI-методы: R8 не должен их переименовывать, символы зашиты в .so
# как Java_dev_flicker_libbox_<Класс>_<метод> (их там 1252).
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# ---------------------------------------------------------------------------
# v4.10.0: JNA + libtgwsproxy.so (Telegram-туннель).
#
# JNA ищет C-символы ПО ИМЕНАМ МЕТОДОВ интерфейса (TgWsLibrary.StartProxy ->
# символ StartProxy в .so). Если R8 переименует или вырежет метод, вызов
# упадёт с UnsatisfiedLinkError уже в рантайме. Отсюда keep всех членов
# интерфейса и всех классов JNA.
#
# Сейчас isMinifyEnabled = false и правила не применяются — они нужны ровно
# на тот случай, если minify когда-нибудь включат (см. шапку файла).
# ---------------------------------------------------------------------------
-keep interface dev.flicker.vpn.core.tgws.TgWsLibrary { *; }
-keep class dev.flicker.vpn.core.tgws.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * implements com.sun.jna.Library { *; }
# JNA ссылается на AWT и на java.lang.reflect.Proxy, которых в Android нет
# или они урезаны; это нормально (ветки для десктопа), но R8 ругается.
-dontwarn java.awt.**
-dontwarn com.sun.jna.**

# Вложенные proxy-классы libbox (Libbox$proxyCommandClientHandler и т.п.):
# их конструкторы вызывает Go-сторона через go.Seq по имени.
-keepclassmembers class dev.flicker.libbox.**$* {
    <init>(...);
    public *;
}

# ViewBinding: bind()/inflate() ищутся рефлексией в сгенерированном коде
-keep class dev.flicker.vpn.databinding.** { *; }
-keepclassmembers class dev.flicker.vpn.databinding.** {
    public static ** bind(android.view.View);
    public static ** inflate(...);
}

# Kotlin metadata и coroutines serviceLoader
-keep class kotlin.Metadata { *; }
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.android.AndroidDispatcherFactory { *; }
-keepclassmembers class kotlinx.coroutines.android.AndroidExceptionPreHandler { *; }

# Компоненты из манифеста — AGP держит их сам, это дешёвая страховка
-keep class dev.flicker.vpn.FlickerApp { *; }
-keep class dev.flicker.vpn.service.** { *; }
-keep class dev.flicker.vpn.receiver.** { *; }

# Читаемый стектрейс краша: без этого mapping.txt обязателен для расшифровки,
# а без SourceFile/LineNumberTable он бесполезен наполовину.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
-keepattributes Signature,InnerClasses,EnclosingMethod,*Annotation*

# НЕ включай -overloadaggressively и -repackageclasses для GoMobile-пакетов:
# это ломает JNI-имена, и приложение упадёт при первом обращении к ядру.

# Отчёт о том, что именно вырезано — обязательно сохраняй вместе с релизом.
-printusage   build/outputs/mapping/release/usage.txt
-printmapping build/outputs/mapping/release/mapping.txt
-printseeds   build/outputs/mapping/release/seeds.txt

# ---------------------------------------------------------------------------
# v4.12.0: движок обхода DPI — порт из EwenLoy/ByeByeDPI-x-tg.
#
# TProxyService ищется ПО ИМЕНИ из JNI_OnLoad libhev-socks5-tunnel.so
# (FindClass "dev/flicker/vpn/core/TProxyService", PKGNAME задан в
# src/main/jni/Application.mk) — если R8 переименует класс, RegisterNatives
# упадёт при загрузке библиотеки.
# ByeDpiProxy — JNI-символы Java_dev_flicker_vpn_core_ByeDpiProxy_* зашиты
# в libbyedpi.so (cpp/native-lib.c).
# Правила дублируют keep-правила самого эталона (его proguard-rules.pro).
# ---------------------------------------------------------------------------
-keep class dev.flicker.vpn.core.TProxyService { *; }
-keep class dev.flicker.vpn.core.ByeDpiProxy { *; }
