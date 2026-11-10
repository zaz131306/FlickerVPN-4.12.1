#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
extract-core.py — достаёт нативное ядро из РАБОЧЕГО APK и кладёт его туда,
где его подхватит Gradle: android/app/src/main/jniLibs/<abi>/libflickerbox.so

ЗАЧЕМ
-----
Ядро (libflickerbox.so, ~62 МБ) — это 78% веса приложения. Без него APK
собирается, ставится и умирает на System.loadLibrary("flickerbox")
с UnsatisfiedLinkError. Честный способ получить ядро — собрать его из
Go-исходников (tools/build-libbox-aar.sh), но это Go 1.26 + NDK 27.2 +
JDK 17 + ~16 ГБ диска + 30-50 минут. Этот скрипт — короткий путь: ядро
уже лежит внутри APK, который на вашем телефоне доходил до этапа
подключения, то есть ЗАВЕДОМО грузится на вашем устройстве.

ЧТО ПРОВЕРЯЕТ
-------------
1. Что найденные записи — валидный ELF64 (магия, класс, тип DYN).
2. Выравнивание PT_LOAD-сегментов. Это решает, каким должно быть
   useLegacyPackaging в app/build.gradle.kts:
     Align = 0x4000 (16 КБ) -> можно false (.so маппится прямо из APK)
     Align = 0x1000 ( 4 КБ) -> ОБЯЗАТЕЛЬНО true, иначе на Android 15+
                               с 16-килобайтной страницей dlopen падает.
   На APK 4_0_3-arm64-FIXED3 измерено 0x1000 у всех четырёх LOAD.
3. Что JNI-символы внутри .so соответствуют пакетам dev.flicker.* —
   иначе jar с классами и .so окажутся от разных сборок.

Использование:
    python3 tools/extract-core.py                    # APK ищется сам
    python3 tools/extract-core.py путь/до/app.apk    # указать явно
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import sys
import zipfile

LIB_NAME = "libflickerbox.so"
# Пакеты, которые экспортирует gomobile-связка. Нужны и в .so (JNI-символы),
# и в jar с классами (tools/make-core-jar.py).
CORE_PACKAGES = ("go/", "dev/flicker/libbox/", "dev/flicker/mobile/")


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"\n\033[1;31m[ошибка]\033[0m {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"\033[1;32m[ ok ]\033[0m {msg}")


def info(msg: str) -> None:
    print(f"\033[1;34m[info]\033[0m {msg}")


def find_apk(explicit: str | None) -> str:
    """Ищем APK: явно указанный -> project/*.apk -> любой в дереве.

    Корней несколько: скрипт живёт в <repo>/tools/, а APK-донор обычно лежит
    рядом с репозиторием (в рабочей копии это ../project/), поэтому обходим
    и сам репозиторий, и его родителя.
    """
    if explicit:
        if not os.path.isfile(explicit):
            die(f"файл не найден: {explicit}")
        return explicit

    here = os.path.dirname(os.path.abspath(__file__))
    roots = [os.path.dirname(here), os.path.dirname(os.path.dirname(here)), os.getcwd()]
    seen: set[str] = set()
    cands: list[tuple[int, str]] = []
    for root in roots:
        for base in ("project", ".", "release", "dist", "download", "downloads"):
            d = os.path.join(root, base)
            if not os.path.isdir(d) or d in seen:
                continue
            seen.add(d)
            for name in os.listdir(d):
                if not name.lower().endswith(".apk"):
                    continue
                p = os.path.abspath(os.path.join(d, name))
                cands.append((os.path.getsize(p), p))
    if not cands:
        die(
            "APK-донор не найден. Положите рабочий APK в project/ или укажите путь:\n"
            "    python3 tools/extract-core.py /путь/до/FlickerVPN.apk"
        )
    # без дублей, крупнейший первым
    uniq = {p: s for s, p in cands}
    ordered = sorted(((s, p) for p, s in uniq.items()), reverse=True)
    if len(ordered) > 1:
        info("найдено несколько APK, беру самый большой (в нём точно есть .so):")
        for size, p in ordered:
            mark = " ->" if p == ordered[0][1] else "   "
            print(f"     {mark} {p}  {size / 1048576:.2f} МБ")
    return ordered[0][1]


def check_elf(data: bytes, name: str) -> None:
    """Минимальная валидация ELF64 без внешних утилит."""
    if data[:4] != b"\x7fELF":
        die(f"{name}: это не ELF (магия {data[:4]!r})")
    if data[4] != 2:
        die(f"{name}: ожидается 64-битный ELF (класс {data[4]})")
    e_type = struct.unpack_from("<H", data, 16)[0]
    if e_type != 3:  # ET_DYN
        die(f"{name}: ожидается shared object (ET_DYN=3), получено e_type={e_type}")
    if struct.unpack_from("<H", data, 18)[0] != 0xB7:  # EM_AARCH64
        machine = struct.unpack_from("<H", data, 18)[0]
        if machine != 0x3E:  # EM_X86_64
            die(f"{name}: неожиданная архитектура e_machine={machine:#x}")


def load_aligns(data: bytes) -> list[int]:
    """Align всех PT_LOAD-сегментов."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    out = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_align = struct.unpack_from("<Q", data, o + 48)[0]
        out.append(p_align)
    if not out:
        die("в ELF не нашлось ни одного PT_LOAD-сегмента")
    return out


def jni_symbols(data: bytes) -> dict[str, int]:
    """Считаем JNI-экспорты по пакетам — сверяем .so с классами ядра."""
    counts: dict[str, int] = {}
    for sym in set(re.findall(rb"Java_[A-Za-z0-9_]+", data)):
        s = sym.decode()
        if s.startswith("Java_dev_flicker_libbox"):
            counts["dev.flicker.libbox"] = counts.get("dev.flicker.libbox", 0) + 1
        elif s.startswith("Java_dev_flicker_mobile"):
            counts["dev.flicker.mobile"] = counts.get("dev.flicker.mobile", 0) + 1
        elif s.startswith("Java_go_"):
            counts["go (рантайм gomobile)"] = counts.get("go (рантайм gomobile)", 0) + 1
    return counts


def main() -> None:
    apk = find_apk(sys.argv[1] if len(sys.argv) > 1 else None)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    jni_root = os.path.join(root, "android", "app", "src", "main", "jniLibs")

    info(f"APK-донор : {os.path.relpath(apk, root) if apk.startswith(root) else apk}")
    info(f"           {os.path.getsize(apk) / 1048576:.2f} МБ")

    z = zipfile.ZipFile(apk)
    entries = [i for i in z.infolist() if i.filename.startswith("lib/") and i.filename.endswith(".so")]
    if not entries:
        die(f"в {os.path.basename(apk)} нет ни одной lib/<abi>/*.so — это не тот APK")

    print()
    info("нативные библиотеки в APK:")
    for i in entries:
        abi = i.filename.split("/")[1]
        method = "STORED " if i.compress_type == 0 else "DEFLATE"
        print(
            f"     {abi:<14} {i.file_size / 1048576:7.2f} МБ несжато -> "
            f"{i.compress_size / 1048576:6.2f} МБ в zip  [{method}]"
        )

    if not any(i.filename.endswith(LIB_NAME) for i in entries):
        die(f"среди них нет {LIB_NAME} — ядро называется иначе, правьте LIB_NAME в скрипте")

    os.makedirs(jni_root, exist_ok=True)
    worst_align = 1 << 62
    wrote: list[str] = []

    for i in entries:
        if not i.filename.endswith(LIB_NAME):
            continue
        abi = i.filename.split("/")[1]
        dst_dir = os.path.join(jni_root, abi)
        os.makedirs(dst_dir, exist_ok=True)
        dst = os.path.join(dst_dir, LIB_NAME)

        data = z.read(i.filename)
        if len(data) != i.file_size:
            die(f"{i.filename}: прочитано {len(data)} из {i.file_size} байт")
        check_elf(data, i.filename)

        with open(dst, "wb") as f:
            f.write(data)
        wrote.append(dst)

        aligns = load_aligns(data)
        worst_align = min(worst_align, min(aligns))

        print()
        ok(f"{abi}/{LIB_NAME}: {len(data)} байт, ELF64 shared object")
        print(f"     PT_LOAD align: {', '.join(hex(a) for a in aligns)}")

        syms = jni_symbols(data)
        if not syms:
            die(f"{abi}: в .so нет ни одного JNI-символа Java_* — библиотека не та")
        print("     JNI-экспорт:")
        for pkg, n in sorted(syms.items(), key=lambda kv: -kv[1]):
            print(f"       {n:>5}  Java_{pkg.replace('.', '_')}_*")

    # ---- вывод о useLegacyPackaging ----
    gradle = os.path.join(root, "android", "app", "build.gradle.kts")
    print()
    if worst_align >= 0x4000:
        ok(f"выравнивание {hex(worst_align)} (16 КБ) — годится для useLegacyPackaging = false")
    else:
        info(f"выравнивание {hex(worst_align)} ({worst_align // 1024} КБ) — НЕ 16 КБ")
        print(
            "     На Android 15+ с 16-килобайтной страницей dlopen такой библиотеки\n"
            "     из несжатого APK падает. Требуется:\n"
            "         useLegacyPackaging = true   // в app/build.gradle.kts, jniLibs {}\n"
            "     В этом проекте оно уже выставлено в true — проверьте, что не сбили."
        )
    if os.path.isfile(gradle):
        txt = open(gradle, encoding="utf-8").read()
        if "useLegacyPackaging = true" in txt:
            ok("build.gradle.kts: useLegacyPackaging = true — соответствует измеренному выравниванию")
        elif "useLegacyPackaging = false" in txt:
            if worst_align < 0x4000:
                print(
                    "\n\033[1;31m[ошибка]\033[0m build.gradle.kts содержит useLegacyPackaging = false,\n"
                    "          а измеренное выравнивание .so меньше 16 КБ.\n"
                    "          Приложение не запустится на 16KB-устройствах. Исправьте на true.",
                    file=sys.stderr,
                )
                sys.exit(1)
            ok("build.gradle.kts: useLegacyPackaging = false — выравнивание позволяет")

    print()
    ok(f"записано файлов: {len(wrote)}")
    for p in wrote:
        print(f"     {os.path.relpath(p, root)}   {os.path.getsize(p) / 1048576:.2f} МБ")

    print(
        "\n\033[1mдальше\033[0m — нужны Java-классы ядра (go/*, dev/flicker/libbox/*,\n"
        "dev/flicker/mobile/*). Одной .so мало: Kotlin обращается к\n"
        "dev.flicker.libbox.SetupOptions и без классов не скомпилируется.\n"
        "\n"
        "    1) вытащите classes.dex из того же APK:\n"
        f"       python3 -c \"import zipfile;zipfile.ZipFile('{os.path.basename(apk)}')"
        ".extract('classes.dex','.')\"\n"
        "    2) конвертируйте dex -> jar (нужна Java, dex2jar качается одним архивом):\n"
        "       d2j-dex2jar classes.dex        # даст classes-dex2jar.jar\n"
        "    3) соберите из него jar только с классами ядра:\n"
        "       python3 tools/make-core-jar.py classes-dex2jar.jar\n"
        "\n"
        "Подробно: BUILD-NOW.md\n"
    )


if __name__ == "__main__":
    main()
