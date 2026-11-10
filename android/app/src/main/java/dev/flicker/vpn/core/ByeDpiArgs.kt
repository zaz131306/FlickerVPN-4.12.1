// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn.core

/**
 * Построитель аргументов командной строки для byedpi 17.3 и набор пресетов.
 *
 * byedpi — консольная программа: весь её «конфиг» это argv. Обёртка
 * [ByeDpiProxy.startProxy] передаёт массив строк прямо в main(argc, argv).
 *
 * Все буквы опций сверены с usage-строкой самого byedpi (main.c:66-123),
 * а не взяты из чужого UI:
 *
 *   -i/--ip, -p/--port, -c/--max-conn (512), -b/--buf-size (16384)
 *   -K/--proto <t,h,u,i>   whitelist протоколов: tls, http, udp, ipv4
 *   -H/--hosts <file|:str> whitelist хостов
 *   -s/--split, -d/--disorder, -o/--oob, -q/--disoob, -f/--fake  <pos_t>
 *   -e/--oob-data <char>   свой байт OOB
 *   -n/--fake-sni, -t/--ttl (8), -O/--fake-offset, -l/--fake-data
 *   -r/--tlsrec <pos_t>    разрезать TLS-запись на позиции
 *   -M/--mod-http <h,d,r>  hcsmix, dcsmix, rmspace
 *   -a/--udp-fake <count>  количество UDP-фейков (0)
 *   -g/--def-ttl, -N/--no-domain, -U/--no-udp, -F/--tfo, -Y/--drop-sack
 *   -A/--auto <t,r,s,n,c>  «пробовать desync-параметры после этой опции»
 *   -L/--auto-mode <s,o,n> swop / onreconn / noreconn
 *   -y/--cache-file <path|->, -u/--cache-ttl <sec>  кэш подобранных параметров
 *   -T/--timeout <s[:p:c:b]>, -R/--round <num[-numr]>, -x/--debug <0..2>
 *
 * Формат <pos_t>: offset[:repeats:skip][+flag1[flag2]], флаги — e (end),
 * m (mid), r (rand), h (host), s (sni) и т.д. (main.c:560-570).
 */
object ByeDpiArgs {

    /** argv[0], который ожидает byedpi. */
    private const val ARGV0 = "ciadpi"

    /** Опции, которые нельзя передавать из приложения. */
    private val BLACKLIST = setOf("--help", "--version", "-h", "-v", "-D", "--daemon")

    /**
     * Базовые опции, общие для всех пресетов.
     *
     * Значения — дефолты byedpi (main.c:75,79) и одновременно дефолты
     * ByeByeDPI-x-tg (UISettings: maxConnections=512, bufferSize=16384).
     */
    private const val BASE = "-c512 -b16384"

    /**
     * Разбивает командную строку на токены с учётом кавычек.
     *
     * Взято из EwenLoy/ByeByeDPI-x-tg (utility/ArgumentsUtils.kt), где, в свою
     * очередь, основано на https://gist.github.com/raymyers/8077031.
     * Поведение сохранено один в один, чтобы строки из их настроек можно было
     * переносить сюда без правок.
     */
    fun shellSplit(string: CharSequence): List<String> {
        val tokens: MutableList<String> = ArrayList()
        var quoteChar = ' '
        var escaping = false
        var quoting = false
        var lastCloseQuoteIndex = Int.MIN_VALUE
        var current = StringBuilder()

        for (i in string.indices) {
            val c = string[i]
            if (escaping) {
                current.append(c)
                escaping = false
            } else if (c == '\\' && quoting) {
                if (i + 1 < string.length && string[i + 1] == quoteChar) {
                    escaping = true
                } else {
                    current.append(c)
                }
            } else if (quoting && c == quoteChar) {
                quoting = false
                lastCloseQuoteIndex = i
            } else if (!quoting && (c == '\'' || c == '"')) {
                quoting = true
                quoteChar = c
            } else if (!quoting && Character.isWhitespace(c)) {
                if (current.isNotEmpty() || lastCloseQuoteIndex == i - 1) {
                    tokens.add(current.toString())
                    current = StringBuilder()
                }
            } else {
                current.append(c)
            }
        }
        if (current.isNotEmpty() || lastCloseQuoteIndex == string.length - 1) {
            tokens.add(current.toString())
        }
        return tokens
    }

    /**
     * Присутствуют ли в списке свои --ip/--port.
     *
     * Проверяются обе формы: длинная (`--ip 1.2.3.4`, `--ip=1.2.3.4`) и короткая
     * склеенная (`-i1.2.3.4`). Если пользователь задал адрес сам — наш не
     * добавляем, иначе будет дубль и byedpi возьмёт последний.
     */
    private fun hasOpt(tokens: List<String>, short: String, long: String): Boolean =
        tokens.any {
            it == long || it.startsWith("$long=") ||
                it == short || (it.startsWith(short) && it.length > short.length && !it.startsWith("$short-"))
        }

    /**
     * Собирает argv из человекочитаемой командной строки.
     *
     * @param command строка вида `-Kt,h -o1 -e a -An` (argv[0] и --ip/--port
     *                указывать не нужно — подставятся сами).
     * @param host    адрес, на котором слушать. Для sing-box socks-outbound
     *                это всегда 127.0.0.1.
     * @param port    порт SOCKS5.
     */
    fun build(command: String, host: String, port: Int): Array<String> {
        val tokens = shellSplit(command)
            // argv0 и всё до первого флага — отбросить (пользователь мог
            // вставить «ciadpi» в начало строки)
            .dropWhile { !it.startsWith("-") }
            .filter { it !in BLACKLIST }

        val prefix = buildList {
            if (!hasOpt(tokens, "-i", "--ip")) addAll(listOf("--ip", host))
            if (!hasOpt(tokens, "-p", "--port")) addAll(listOf("--port", port.toString()))
        }
        return (listOf(ARGV0) + prefix + tokens).toTypedArray()
    }

    /** Имя пресета + сама командная строка + зачем он нужен. */
    data class Preset(val id: String, val title: String, val command: String, val note: String)

    /**
     * Пресеты для перебора.
     *
     * Базовый (первый) — дефолт ByeByeDPI-x-tg, собранный по их же логике
     * UISettings → uiargs: desyncMethod=OOB, splitPosition=1, oobChar='a',
     * desyncHttp+desyncHttps+desyncUdp=true, udpFakeCount=1, hostsMode=Disable.
     * Это единственное значение в списке, которое «проверено чужим продом».
     *
     * Остальные — систематический перебор тех же пяти методов desync
     * (-s/-d/-o/-q/-f), которые byedpi поддерживает, плюс два уточнения
     * (разрез TLS-записи и позиция «после host»).
     *
     * ПРО `-e a`, А НЕ `-e97`. UI ByeByeDPI-x-tg кладёт туда десятичный код
     * символа: `-e${oobChar[0].code.toByte()}` → `-e97` для 'a'. Но byedpi
     * парсит опцию через parse_cform(dp->oob_char, 1, optarg, strlen(optarg))
     * (main.c:1123-1128), то есть как СИМВОЛ, а не как число: `-e97` означает
     * байт '9'. Здесь используется однозначная символьная форма.
     */
    val PRESETS: List<Preset> = listOf(
        /*
         * v4.10.1: ЭТАЛОННЫЙ ПРЕСЕТ — байт-в-байт как в ByeByeDPI-x-tg.
         *
         * ЗАЧЕМ ОН ОТДЕЛЬНО. Прежний дефолт («oob») считался портированным
         * дефолтом ByeByeDPI-x-tg, но отличался от него одним параметром, и
         * это отличие меняет БАЙТЫ НА ПРОВОДЕ.
         *
         * Эталон (EwenLoy/ByeByeDPI-x-tg, ByeDpiProxyPreferences.uiargs при
         * дефолтных UISettings: desyncMethod=OOB, splitPosition=1,
         * oobChar="a", desyncHttp+desyncHttps+desyncUdp=true, udpFakeCount=1,
         * hostsMode=Disable, остальные флаги false) собирает ровно:
         *
         *     ciadpi -i127.0.0.1 -p1080 -c512 -b16384 -Kt,h -o1 -e97 -An -Ku -a1 -An
         *
         * Наш прежний «oob» давал:
         *
         *     ciadpi --ip … --port … -c512 -b16384 -Kt,h -o1 -e a -An -Ku -a1
         *
         * Отличия и их цена:
         *
         * 1. `-e97` против `-e a` — СУЩЕСТВЕННО. byedpi парсит `-e` через
         *    parse_cform(dp->oob_char, 1, optarg, strlen(optarg))
         *    (main.c:1123-1128), а parse_cform (main.c:198-230) при blen=1
         *    копирует ровно ОДИН символ и возвращает 1, то есть значение
         *    валидно в обоих случаях:
         *       `-e97` → oob_char = '9' (0x39)
         *       `-e a` → oob_char = 'a' (0x61)
         *    Байт уходит в поток как OOB-данные (desync.c:604,618). Прежняя
         *    правка на `-e a` была верна по сути (это действительно символ, а
         *    не десятичный код), но она молча поменяла рабочий байт на другой.
         *    Раз DPI у провайдера реагирует на конкретное искажение, менять
         *    его «на глаз» нельзя — поэтому эталонный вариант возвращается
         *    как есть и делается дефолтным.
         *
         * 2. Хвостовой `-An` — НЕ СУЩЕСТВЕННО, но возвращён для точности.
         *    `-A` вызывает add_group() (main.c:854-866), буква 'n' в нём —
         *    no-op (main.c:881-882). Пустая группа в конце всё равно
         *    добавляется самим byedpi при all_limited=1 (main.c:1272-1277),
         *    поэтому лишний `-An` даёт ещё одну такую же пустую группу и на
         *    поведение не влияет. Оставляем, чтобы argv совпадал дословно.
         *
         * 3. `-i`/`-p` против `--ip`/`--port` — эквивалент: в таблице
         *    длинных имён (main.c:138-139) это те же 'i' и 'p'. Адрес и порт
         *    намеренно НЕ зашиты в строку пресета — их подставляет build()
         *    из фактического BYEDPI_PORT, иначе пресет разошёлся бы с кодом
         *    при смене порта.
         *
         * Итого argv этого пресета отличается от эталонного только номером
         * порта и длинной формой -i/-p, которые на поведение не влияют.
         */
        Preset(
            "ref", "Эталон ByeByeDPI-x-tg (дословно)",
            "$BASE -Kt,h -o1 -e97 -An -Ku -a1 -An",
            "Ровно та командная строка, которую ByeByeDPI-x-tg собирает при " +
                "своих настройках по умолчанию (OOB, позиция 1, oob-байт '9', " +
                "TLS+HTTP+UDP, 1 UDP-фейк). Если обход работает в том " +
                "приложении — начинать проверку надо с этого пресета."
        ),
        Preset(
            "oob", "OOB (oob-байт 'a')",
            "$BASE -Kt,h -o1 -e a -An -Ku -a1",
            "То же, что эталон, но OOB-байт — 'a' вместо '9'. Разрез после " +
                "1-го байта, второй кусок уходит как out-of-band данные. " +
                "Сравнение этих двух пресетов показывает, важен ли провайдеру " +
                "конкретный байт OOB."
        ),
        Preset(
            "disoob", "DISOOB (обратный порядок + OOB)",
            "$BASE -Kt,h -q1 -e a -An -Ku -a1",
            "Как OOB, но куски отправляются в обратном порядке. Помогает там, " +
                "где DPI собирает ClientHello из потока по порядку."
        ),
        Preset(
            "split", "Split (простой разрез)",
            "$BASE -Kt,h -s1 -An -Ku -a1",
            "ClientHello делится на два TCP-сегмента без лишних приёмов. " +
                "Минимальная вероятность сломать соединение."
        ),
        Preset(
            "split-host", "Split по позиции host",
            "$BASE -Kt,h -s1+h -An -Ku -a1",
            "Разрез привязан к позиции заголовка Host/SNI, а не к фиксированному " +
                "смещению. Точнее, но требует от byedpi разобрать пакет."
        ),
        Preset(
            "disorder", "Disorder (обратный порядок)",
            "$BASE -Kt,h -d1 -An -Ku -a1",
            "Куски уходят в обратном порядке, без OOB."
        ),
        Preset(
            "fake", "Fake-пакет (TTL 8, SNI www.iana.org)",
            "$BASE -Kt,h -f1 -t8 -nwww.iana.org -An -Ku -a1",
            "Вперёд отправляется поддельный ClientHello с маленьким TTL, чтобы он " +
                "умер по дороге и достался только DPI. Значения -t8 и -n — " +
                "дефолты ByeByeDPI-x-tg."
        ),
        Preset(
            "tlsrec", "OOB + разрез TLS-записи",
            "$BASE -Kt,h -o1 -e a -r1+s -An -Ku -a1",
            "Дополнительно режет саму TLS-запись на позиции SNI (-r1+s). " +
                "Для фильтров, которые смотрят на границы записей."
        ),
        Preset(
            "tcp-only", "Только TCP (без UDP-фейков)",
            "$BASE -Kt,h -o1 -e a -An",
            "Как базовый, но без -Ku/-a1. Для провайдеров, где UDP-фейки " +
                "ломают QUIC/звонки."
        ),
        Preset(
            "auto", "Автоподбор силами byedpi",
            "$BASE -Kt,h -o1 -e a -An -Ku -a1 -A t,r,s,n -L s -u 300",
            "ВКЛЮЧАЕТ СОБСТВЕННЫЙ автоподбор byedpi: -A перечисляет методы, " +
                "которые стоит пробовать, -L s (swop) разрешает менять их местами, " +
                "-u 300 кэширует подобранные параметры на IP на 5 минут. " +
                "Медленнее на первом соединении к каждому хосту, зато " +
                "подстраивается сам. Полный кэш — с -y <путь>."
        ),
    )

    /**
     * Пресет по умолчанию.
     *
     * v4.10.1: был «oob», стал «ref» — дословная командная строка
     * ByeByeDPI-x-tg. Причина в комментарии к PRESETS: прежнее значение
     * отличалось от рабочего эталона OOB-байтом ('a' вместо '9'), а это
     * единственное место, где мы расходились с приложением, в котором обход
     * у пользователя работает.
     *
     * Значение важно и как fallback: [preset] при неизвестном id возвращает
     * PRESETS.first(), то есть тоже «ref».
     */
    const val DEFAULT_PRESET_ID = "ref"

    fun preset(id: String?): Preset =
        PRESETS.firstOrNull { it.id == id } ?: PRESETS.first()

    /**
     * Аргументы для [ByeDpiProxy.startProxy] из пресета или произвольной строки.
     *
     * @param command если не null/не пусто — используется вместо пресета
     *                (режим «своя командная строка», как CMD-настройки
     *                в ByeByeDPI-x-tg).
     */
    fun argsFor(presetId: String?, command: String?, host: String, port: Int): Array<String> =
        build(command?.takeIf { it.isNotBlank() } ?: preset(presetId).command, host, port)
}
