// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core.tgws

import android.util.Log
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

/**
 * v4.10.0: JNA-обвязка над `libtgwsproxy.so` — Rust-ядро MTProto-WS-прокси
 * (форк Flowseal/tg-ws-proxy, тот же бинарник, что кладёт в APK
 * EwenLoy/ByeByeDPI-x-tg).
 *
 * ---------------------------------------------------------------------------
 *  ПОЧЕМУ JNA, А НЕ JNI
 * ---------------------------------------------------------------------------
 *  Rust-библиотека экспортирует обычные C-символы (`#[no_mangle] extern "C"`),
 *  а не `Java_<пакет>_<класс>_<метод>`. Значит:
 *    * писать JNI-обёртку и пересобирать Rust не нужно;
 *    * .so НЕ привязана к имени нашего пакета — её можно положить как есть;
 *    * вызовы идут через JNA (libjnidispatch.so из `net.java.dev.jna:jna@aar`).
 *  Ровно так же сделано в amurcanov/tg-ws-proxy-android и в ByeByeDPI-x-tg.
 *
 * ---------------------------------------------------------------------------
 *  КРИТИЧНО: СПИСОК МЕТОДОВ СОВПАДАЕТ С РЕАЛЬНЫМ ЭКСПОРТОМ .so
 * ---------------------------------------------------------------------------
 *  Это не «взяли у тех же парней и не глядя». Экспорт прочитан из секции
 *  .dynsym обеих библиотек в `src/main/tglibs/`:
 *
 *      FreeString, GetSecretWithPrefix, GetStats, SetCfProxyCacheDir,
 *      SetCfProxyConfig, SetPoolSize, SetSecret, StartProxy, StopProxy
 *                                                        (9 символов, обе ABI)
 *
 *  Интерфейс `ProxyLibrary` из amurcanov/tg-ws-proxy-android объявляет ШЕСТЬ
 *  МЕТОДОВ, КОТОРЫХ В НАШЕЙ .so НЕТ:
 *      SetBufferSizeKb, SetCfWorkerDomains, SetFakeTlsDomain,
 *      SetDisableSecure, SetForceTestDc, SetProxyProtocol
 *  Их нет, потому что наша .so собрана из другого форка. JNA разрешает символы
 *  ЛЕНИВО — при первом вызове метода, поэтому сборка прошла бы успешно, а
 *  приложение падало бы в рантайме с `UnsatisfiedLinkError` в тот момент, когда
 *  пользователь нажимает кнопку. Найти это вслепую почти невозможно.
 *  Правильный образец — `ewenloy/tgws/NativeProxy.kt` из ByeByeDPI-x-tg:
 *  он описывает ровно эти 9 символов. Ниже — он же, плюс `SetSecret`
 *  (есть в экспорте, у ewenloy не используется).
 *
 *  ПРОВЕРИТЬ ПОСЛЕ ОБНОВЛЕНИЯ .so (символы могут поменяться):
 *      nm -D --defined-only src/main/tglibs/arm64-v8a/libtgwsproxy.so | grep ' T '
 *  и сверить со списком методов [TgWsLibrary].
 *
 * ---------------------------------------------------------------------------
 *  СЕМАНТИКА ВЫЗОВОВ (по src/lib.rs того же форка)
 * ---------------------------------------------------------------------------
 *  StartProxy(host, port, dcIps, secret, verbose) -> Int
 *      0   поднялся, сокет слушает (функция ждёт bind перед возвратом);
 *      -1  прокси уже запущен в этом процессе;
 *      -3  не удалось занять host:port.
 *      НЕ БЛОКИРУЕТ надолго: accept-цикл крутится в tokio-задаче.
 *  StopProxy() -> Int
 *      0 остановлен, -1 не был запущен. БЛОКИРУЕТ до ~2 с (block_on с
 *      timeout) — вызывать только с фонового потока.
 *  Глобальный tokio-рантайм НЕ дропается никогда, поэтому Start/Stop можно
 *  повторять в пределах одного процесса. Процесс при этом отдельный
 *  (`:tgws`) — см. TgWsService.
 *
 *  GetSecretWithPrefix() / GetStats() возвращают `*mut c_char`, созданный
 *  `CString::into_raw()`. Память чужая, GC о ней не знает — ОБЯЗАТЕЛЬНО
 *  освободить через FreeString(), иначе течёт по ~100 байт на каждый опрос
 *  статистики (а опрос каждые 5 с).
 */
interface TgWsLibrary : Library {

    fun StartProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int

    fun StopProxy(): Int

    /** 0..16; 0 отключает преконнект пула WS-соединений. */
    fun SetPoolSize(size: Int)

    /** 32 hex-символа. Некорректное значение Rust молча игнорирует. */
    fun SetSecret(secret: String)

    /** Куда складывать кэш списка доменов CloudFlare (иначе тянет каждый старт). */
    fun SetCfProxyCacheDir(cacheDir: String)

    /**
     * @param enabled    1 — ходить через CloudFlare (основной режим обхода).
     * @param priority   зарезервировано форком, всегда передаём 1.
     * @param userDomain свой домен-воркер; "" — использовать встроенный список.
     */
    fun SetCfProxyConfig(enabled: Int, priority: Int, userDomain: String)

    /** `dd<32hex>` — то, что вписывается в Telegram как secret. */
    fun GetSecretWithPrefix(): Pointer?

    /** `total=… active=… ws=… tcp_fb=… cf=… bad=… err=… pool=…/… up=… down=…` */
    fun GetStats(): Pointer?

    fun FreeString(p: Pointer)
}

/**
 * Единственная точка входа в натив. Никогда не бросает наружу: все ошибки
 * складываются в [loadError] и показываются пользователю текстом.
 *
 * Почему так. `Native.load` кидает `UnsatisfiedLinkError` (это Error, не
 * Exception), если .so не доехала в APK — например, сборка под armeabi-v7a,
 * где `libflickerbox.so` всё равно нет, или abiFilters отфильтровал библиотеку.
 * Ловить нужно Throwable и показывать внятную причину, а не ронять сервис.
 */
object TgWsNative {

    private const val TAG = "FlickerTgWs"

    /** Имя без `lib` и `.so` — JNA сам подставит префикс и расширение. */
    private const val LIB = "tgwsproxy"

    @Volatile
    private var lib: TgWsLibrary? = null

    @Volatile
    var loadError: String? = null
        private set

    val ready: Boolean get() = lib != null

    /**
     * @param nativeLibraryDir `applicationInfo.nativeLibraryDir` того процесса,
     *   где живёт библиотека. Прописываем в `jna.library.path` ДО первого
     *   обращения к классам JNA: JNA читает это свойство в статическом
     *   инициализаторе NativeLibrary, то есть один раз и навсегда.
     *   На Android JNA и без этого находит .so через System.loadLibrary, но
     *   явный путь убирает расхождение между прошивками.
     */
    @Synchronized
    fun init(nativeLibraryDir: String?) {
        if (lib != null) return
        try {
            if (!nativeLibraryDir.isNullOrBlank()) {
                val cur = System.getProperty("jna.library.path").orEmpty()
                val merged = if (cur.isBlank()) nativeLibraryDir else "$nativeLibraryDir${java.io.File.pathSeparator}$cur"
                System.setProperty("jna.library.path", merged)
                System.setProperty("jna.boot.library.path", merged)
            }
            lib = Native.load(LIB, TgWsLibrary::class.java)
            loadError = null
            Log.i(TAG, "libtgwsproxy.so загружена")
        } catch (t: Throwable) {
            lib = null
            loadError = "${t.javaClass.simpleName}: ${t.message ?: "нет сообщения"}"
            Log.e(TAG, "не удалось загрузить lib$LIB.so", t)
        }
    }

    private fun api(): TgWsLibrary? = lib

    // -----------------------------------------------------------------------
    //  Обёртки. Каждая возвращает результат или пишет причину в loadError.
    //  Все вызываются С ФОНОВОГО ПОТОКА — StopProxy блокирует до 2 с.
    // -----------------------------------------------------------------------

    /** @return код StartProxy, или null если натив недоступен. */
    fun startProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Boolean): Int? {
        val a = api() ?: return null
        return try {
            a.StartProxy(host, port, dcIps, secret, if (verbose) 1 else 0)
        } catch (t: Throwable) {
            loadError = "StartProxy: ${t.javaClass.simpleName}: ${t.message}"
            Log.e(TAG, "StartProxy", t)
            null
        }
    }

    fun stopProxy(): Int? {
        val a = api() ?: return null
        return try {
            a.StopProxy()
        } catch (t: Throwable) {
            loadError = "StopProxy: ${t.javaClass.simpleName}: ${t.message}"
            Log.w(TAG, "StopProxy", t)
            null
        }
    }

    fun setPoolSize(size: Int) = safe("SetPoolSize") { it.SetPoolSize(size.coerceIn(0, 16)) }

    fun setSecret(secret: String) = safe("SetSecret") { it.SetSecret(secret) }

    fun setCfProxyCacheDir(dir: String) = safe("SetCfProxyCacheDir") { it.SetCfProxyCacheDir(dir) }

    fun setCfProxyConfig(enabled: Boolean, priority: Boolean, userDomain: String) =
        safe("SetCfProxyConfig") {
            it.SetCfProxyConfig(if (enabled) 1 else 0, if (priority) 1 else 0, userDomain)
        }

    /** Полный secret с префиксом (`dd…`) — ровно то, что вписывается в Telegram. */
    fun secretWithPrefix(): String? {
        val a = api() ?: return null
        var p: Pointer? = null
        return try {
            p = a.GetSecretWithPrefix()
            p?.getString(0)
        } catch (t: Throwable) {
            Log.w(TAG, "GetSecretWithPrefix", t)
            null
        } finally {
            free(a, p)
        }
    }

    fun stats(): String? {
        val a = api() ?: return null
        var p: Pointer? = null
        return try {
            p = a.GetStats()
            p?.getString(0)
        } catch (t: Throwable) {
            Log.w(TAG, "GetStats", t)
            null
        } finally {
            free(a, p)
        }
    }

    private fun free(a: TgWsLibrary, p: Pointer?) {
        if (p == null) return
        try {
            a.FreeString(p)
        } catch (t: Throwable) {
            Log.w(TAG, "FreeString", t)
        }
    }

    private inline fun safe(name: String, block: (TgWsLibrary) -> Unit) {
        val a = api() ?: return
        try {
            block(a)
        } catch (t: Throwable) {
            loadError = "$name: ${t.javaClass.simpleName}: ${t.message}"
            Log.w(TAG, name, t)
        }
    }

    /**
     * Расшифровка кода возврата StartProxy — текстом для пользователя.
     * Коды взяты из src/lib.rs, а не придуманы.
     */
    fun explainStartCode(code: Int): String = when (code) {
        0 -> "ок"
        -1 -> "прокси уже запущен (StartProxy вернул -1)"
        -3 -> "не удалось занять порт: адрес занят или недоступен (StartProxy вернул -3)"
        else -> "натив вернул неизвестный код $code"
    }
}
