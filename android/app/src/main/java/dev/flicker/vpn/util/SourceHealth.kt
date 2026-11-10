// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.util

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.pow

/**
 * Circuit breaker для источников подписок.
 *
 * ЗАДАЧА: убрать «ошибки http хостинга» и зависания при обновлении.
 *
 * КАК СЕЙЧАС: Repository.refresh() отдаёт в Go-ядро весь список источников и
 * лимит 25. Если источник лежит (404/403/DNS), ядро долбит его на каждом
 * обновлении, пользователь ждёт таймаут, а в логах — шквал HTTP-ошибок. Мёртвый
 * источник к тому же съедает часть квоты в 25 узлов.
 *
 * ЧТО ДЕЛАЕТ:
 *  1. Помнит по каждому источнику число подряд неудач и время последней удачи.
 *  2. После [FAIL_THRESHOLD] неудач замораживает источник — он не попадает в
 *     запрос, обновление проходит быстро и без ошибок.
 *  3. Заморозка снимается по экспоненциальному окну (1 → 2 → 4 → … → 60 мин),
 *     поэтому источник сам возвращается, когда оживёт.
 *  4. Различает «сломан надолго» (400/401/403/404/410) и «сеть моргнула»
 *     (429/5xx/таймаут): первое морозим сразу на максимум.
 *  5. Если заморожены ВСЕ — заморозки сбрасываются. Иначе обновление встанет
 *     навсегда, а это хуже, чем лишняя попытка.
 */
object SourceHealth {

    private const val TAG = "FlickerSources"
    private const val KEY = "source_health_v1"
    private const val PREFS = "flicker_prefs"

    private const val FAIL_THRESHOLD = 3
    private const val COOLDOWN_BASE_MS = 60_000L
    private const val COOLDOWN_MAX_MS = 60 * 60_000L

    private val PERMANENT_CODES = setOf(400, 401, 403, 404, 410, 422)

    private data class State(
        val fails: Int = 0,
        val level: Int = 0,
        val frozenUntil: Long = 0L,
        val lastOkAt: Long = 0L,
        val lastError: String? = null,
    )

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun load(context: Context): MutableMap<String, State> {
        val raw = prefs(context).getString(KEY, null) ?: return mutableMapOf()
        return try {
            val arr = JSONArray(raw)
            val out = mutableMapOf<String, State>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val id = o.optString("id").takeIf { it.isNotBlank() } ?: continue
                out[id] = State(
                    fails = o.optInt("fails"),
                    level = o.optInt("level"),
                    frozenUntil = o.optLong("frozenUntil"),
                    lastOkAt = o.optLong("lastOkAt"),
                    lastError = o.optString("lastError").takeIf { it.isNotBlank() },
                )
            }
            out
        } catch (e: Exception) {
            Log.w(TAG, "не разобрал сохранённое состояние, начинаю с чистого", e)
            mutableMapOf()
        }
    }

    private fun save(context: Context, map: Map<String, State>) {
        val arr = JSONArray()
        map.forEach { (id, s) ->
            arr.put(JSONObject().apply {
                put("id", id)
                put("fails", s.fails)
                put("level", s.level)
                put("frozenUntil", s.frozenUntil)
                put("lastOkAt", s.lastOkAt)
                putOpt("lastError", s.lastError)
            })
        }
        prefs(context).edit().putString(KEY, arr.toString()).apply()
    }

    /**
     * Убирает замороженные источники из JSON-массива.
     * @return пара: отфильтрованный JSON и человекочитаемый список пропущенных (для UI).
     */
    fun filter(context: Context, sourcesJson: String): Pair<String, List<String>> {
        val now = System.currentTimeMillis()
        val health = load(context)
        val out = JSONArray()
        val skipped = mutableListOf<String>()
        try {
            val arr = JSONArray(sourcesJson)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val id = o.optString("id")
                val st = health[id]
                if (st != null && st.frozenUntil > now) {
                    skipped += "${o.optString("name", id)} (ещё ~${(st.frozenUntil - now) / 60_000} мин)"
                    Log.i(TAG, "$id заморожен ещё ${(st.frozenUntil - now) / 60_000} мин (${st.lastError})")
                    continue
                }
                out.put(o)
            }
        } catch (e: Exception) {
            Log.e(TAG, "filter(): sourcesJson не разбирается — отдаю как есть", e)
            return sourcesJson to emptyList()
        }
        if (out.length() == 0) {
            Log.w(TAG, "все источники заморожены — сбрасываю заморозки и пробую все")
            save(context, emptyMap())
            return sourcesJson to emptyList()
        }
        return out.toString() to skipped
    }

    fun recordSuccess(context: Context, id: String) {
        val map = load(context)
        map[id] = State(lastOkAt = System.currentTimeMillis())
        save(context, map)
    }

    /** @param httpCode если известен; null для сетевых ошибок */
    fun recordFailure(context: Context, id: String, httpCode: Int?, message: String?) {
        val map = load(context)
        val prev = map[id] ?: State()
        val permanent = httpCode != null && httpCode in PERMANENT_CODES
        val fails = prev.fails + 1

        if (fails < FAIL_THRESHOLD) {
            map[id] = prev.copy(fails = fails, lastError = message)
            save(context, map)
            Log.w(TAG, "$id: неудача $fails/$FAIL_THRESHOLD ($httpCode $message)")
            return
        }

        val level = if (permanent) prev.level + 2 else prev.level + 1
        val cooldown = if (permanent) {
            COOLDOWN_MAX_MS
        } else {
            (COOLDOWN_BASE_MS * 2.0.pow((level - 1).toDouble())).toLong().coerceAtMost(COOLDOWN_MAX_MS)
        }
        map[id] = prev.copy(
            fails = fails, level = level,
            frozenUntil = System.currentTimeMillis() + cooldown,
            lastError = message,
        )
        save(context, map)
        Log.w(TAG, "$id: ЗАМОРОЖЕН на ${cooldown / 1000}с (уровень $level, permanent=$permanent, $httpCode $message)")
    }

    /** Для экрана настроек: человекочитаемое состояние всех источников. */
    fun describe(context: Context): List<String> {
        val now = System.currentTimeMillis()
        return load(context).map { (id, s) ->
            when {
                s.frozenUntil > now -> "$id — заморожен ещё ${(s.frozenUntil - now) / 60_000} мин: ${s.lastError}"
                s.fails > 0 -> "$id — ${s.fails} неудач подряд: ${s.lastError}"
                else -> "$id — ok (${(now - s.lastOkAt) / 60_000} мин назад)"
            }
        }.sorted()
    }

    /** Кнопка «Забыть ошибки источников» в настройках. */
    fun reset(context: Context) {
        save(context, emptyMap())
        Log.i(TAG, "состояние источников сброшено")
    }
}
