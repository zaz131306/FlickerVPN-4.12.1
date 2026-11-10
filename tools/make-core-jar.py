#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
make-core-jar.py — собирает app/libs/flicker-core.jar ТОЛЬКО из классов ядра.

Вход — jar, полученный из classes.dex рабочего APK (dex2jar):
    d2j-dex2jar classes.dex      ->  classes-dex2jar.jar

В нём лежит ВСЁ приложение: и ядро, и старый код dev.flicker.vpn.*, и все
androidx/kotlin/material. Брать его целиком нельзя:

  * dev/flicker/vpn/**  — СТАРАЯ версия приложения. Новый Kotlin лежит в
    app/src/main/java/dev/flicker/vpn/, и два набора одноимённых классов
    дадут "Duplicate class" на этапе сборки.
  * androidx/**, kotlin/**, com/google/android/material/** — придут из Maven
    (см. dependencies в build.gradle.kts). Дубли — тот же Duplicate class.

Нужны ровно три пакета, которые экспортирует gomobile-связка:

    go/                     рантайм gomobile (Seq, Universe, LoadJNI, ...)
    dev/flicker/libbox/     sing-box experimental/libbox
    dev/flicker/mobile/     Go-фасад FLICKER (Mobile, TunParams, ...)

Именно под них в libflickerbox.so экспортированы JNI-символы — скрипт
tools/extract-core.py печатает их количество (на APK 4_0_3-arm64-FIXED3:
1252 libbox + 33 mobile + 6 go).

БЕЗ ФИЛЬТРАЦИИ ЭТОТ JAR НЕ ВЗЯТЬ: если Python на машине нет, то же самое
делается двумя командами jar (входит в JDK), см. BUILD-NOW.md, шаг 3б.

Использование:
    python3 tools/make-core-jar.py classes-dex2jar.jar
    python3 tools/make-core-jar.py classes-dex2jar.jar -o /путь/flicker-core.jar
"""

from __future__ import annotations

import argparse
import os
import sys
import zipfile

KEEP = ("go/", "dev/flicker/libbox/", "dev/flicker/mobile/")

# Классы, без которых ядро точно не соберётся. Если их нет во входном jar —
# значит, на вход подали не то (например, только classes2.dex).
REQUIRED = (
    "go/Seq.class",
    "dev/flicker/libbox/Libbox.class",
    "dev/flicker/libbox/SetupOptions.class",
    "dev/flicker/libbox/CommandServer.class",
    "dev/flicker/libbox/PlatformInterface.class",
    "dev/flicker/mobile/Mobile.class",
    "dev/flicker/mobile/TunParams.class",
)

# Классы, которые НЕ ДОЛЖНЫ попасть в jar. Их присутствие — признак того,
# что фильтр не сработал, и сборка упадёт на Duplicate class.
FORBIDDEN = (
    "dev/flicker/vpn/",
    "androidx/",
    "kotlin/",
    "kotlinx/",
    "com/google/android/material/",
    "org/jetbrains/",
)


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"\n\033[1;31m[ошибка]\033[0m {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"\033[1;32m[ ok ]\033[0m {msg}")


def info(msg: str) -> None:
    print(f"\033[1;34m[info]\033[0m {msg}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Собрать flicker-core.jar из dex2jar-вывода")
    ap.add_argument("src", help="входной jar (обычно classes-dex2jar.jar)")
    ap.add_argument(
        "-o",
        "--out",
        default=None,
        help="куда положить результат (по умолчанию android/app/libs/flicker-core.jar)",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.src):
        die(f"входной файл не найден: {args.src}")

    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    out = args.out or os.path.join(repo, "android", "app", "libs", "flicker-core.jar")

    info(f"вход : {args.src}  ({os.path.getsize(args.src) / 1048576:.2f} МБ)")
    info(f"выход: {out}")

    zin = zipfile.ZipFile(args.src)
    names = zin.namelist()

    picked: list[zipfile.ZipInfo] = []
    per_pkg: dict[str, int] = {}
    for i in zin.infolist():
        n = i.filename
        if n.endswith("/"):
            continue
        for p in KEEP:
            if n.startswith(p):
                picked.append(i)
                per_pkg[p] = per_pkg.get(p, 0) + 1
                break

    if not picked:
        die(
            "во входном jar не нашлось ни одного класса из пакетов\n"
            + "\n".join(f"    {p}" for p in KEEP)
            + "\n\nПохоже, на вход подан не тот файл. Проверьте:\n"
            "    jar tf " + args.src + " | head -40\n"
            "Должны быть строки вида dev/flicker/libbox/Libbox.class"
        )

    print()
    info("берём классы ядра:")
    for p in KEEP:
        print(f"     {per_pkg.get(p, 0):>5}  {p}**")
    print(f"     {'-' * 5}")
    print(f"     {len(picked):>5}  всего (из {len(names)} записей во входном jar)")

    dropped = len(names) - len(picked)
    info(f"отброшено: {dropped} записей (старый код приложения, androidx, kotlin, material)")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for i in picked:
            zout.writestr(i.filename, zin.read(i.filename))

    # ---- проверки результата ----
    zout = zipfile.ZipFile(out)
    got = set(zout.namelist())

    missing = [r for r in REQUIRED if r not in got]
    if missing:
        print(file=sys.stderr)
        for m in missing:
            print(f"\033[1;31m[ошибка]\033[0m в jar нет обязательного класса: {m}", file=sys.stderr)
        die(
            "входной jar неполный. Возможно, нужные классы лежат в другом\n"
            "dex-файле: в APK их четыре (classes.dex, classes2..4.dex).\n"
            "Сконвертируйте все и объедините, либо подайте тот, где есть go/Seq."
        )

    leaks = [f for f in got if any(f.startswith(fb) for fb in FORBIDDEN)]
    if leaks:
        die(
            "в jar попали посторонние классы (сборка упадёт на Duplicate class):\n    "
            + "\n".join(leaks[:10])
        )

    size = os.path.getsize(out)
    print()
    ok(f"{out}")
    print(f"     {len(got)} классов, {size / 1024:.1f} КБ")
    ok("проверены обязательные классы: " + ", ".join(os.path.basename(r) for r in REQUIRED))
    ok("посторонних пакетов нет (dev.flicker.vpn, androidx, kotlin, material)")

    so = os.path.join(repo, "android", "app", "src", "main", "jniLibs")
    print()
    if os.path.isdir(so):
        found = []
        for abi in sorted(os.listdir(so)):
            p = os.path.join(so, abi, "libflickerbox.so")
            if os.path.isfile(p):
                found.append((abi, os.path.getsize(p)))
        if found:
            ok("нативная часть на месте:")
            for abi, n in found:
                print(f"     jniLibs/{abi}/libflickerbox.so   {n / 1048576:.2f} МБ")
        else:
            info("jniLibs пуст — запустите сначала: python3 tools/extract-core.py")
    else:
        info("jniLibs нет — запустите сначала: python3 tools/extract-core.py")

    print(
        "\n\033[1mдальше\033[0m — собрать APK (см. BUILD-NOW.md):\n"
        "    cd android\n"
        "    ./gradlew --no-daemon :app:assembleRelease\n"
        "\n"
        "Gradle сам подхватит libs/flicker-core.jar и jniLibs/*.so.\n"
        "Если ядра нет, сборка теперь ПАДАЕТ с внятным сообщением, а не\n"
        "выдаёт пустой APK на 5 МБ.\n"
    )


if __name__ == "__main__":
    main()
