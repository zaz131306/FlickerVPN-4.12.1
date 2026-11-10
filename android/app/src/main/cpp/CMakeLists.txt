# SPDX-License-Identifier: GPL-3.0-or-later
#
# Сборка libbyedpi.so — обходчика DPI.
#
# v4.12.0: исходники byedpi и JNI-обёртка native-lib.c взяты ДОСЛОВНО из
# EwenLoy/ByeByeDPI-x-tg v1.0.1-build5 (submodule hufrea/byedpi, commit
# e0fccf68bf74046d0e5b614850d7973c41ec19db, версия 17.3) — это ровно та
# сборка, в которой обход DPI работает у пользователя. Единственное отличие
# native-lib.c — имена JNI-символов (Java_dev_flicker_vpn_core_ByeDpiProxy_*
# вместо Java_io_github_romanvht_byedpi_core_ByeDpiProxy_*): пакет класса
# ByeDpiProxy у нас dev.flicker.vpn.core.
#
# ВАЖНО ПРО ОТЛИЧИЕ ОТ ПРЕЖНЕЙ ВЕРСИИ (byedpi-jni.c, commit ba532298):
# прежняя обёртка разрешала РОВНО ОДИН запуск main() на процесс (флаг
# proxy_started). Эталоная обёртка вместо этого сбрасывает глобальные
# параметры перед каждым запуском (reset_params() = clear_params() +
# default_params) и допускает повторные запуски в одном процессе — именно
# так это работает в ByeByeDPI-x-tg в проде. Флаг g_proxy_running защищает
# только от одновременного двойного старта.
#
# TUN-слой обхода DPI — hev-socks5-tunnel (src/main/jni, задача runNdkBuild
# в build.gradle.kts), как в эталоне; sing-box в режиме обхода больше не
# участвует.
#
# Что нужно для сборки: NDK 27.2.12479018 и CMake 3.22.1 (Android Studio →
# SDK Manager → SDK Tools).

cmake_minimum_required(VERSION 3.22.1)

project(byedpi_native)

set(BYE_DPI_SRC
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/conev.c
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/desync.c
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/extend.c
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/main.c
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/mpool.c
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/packets.c
    ${CMAKE_CURRENT_LIST_DIR}/byedpi/proxy.c
)

add_library(byedpi SHARED ${BYE_DPI_SRC} native-lib.c)
target_include_directories(byedpi PRIVATE byedpi)

target_compile_options(byedpi PRIVATE -std=c99 -O2 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic)
target_compile_definitions(byedpi PRIVATE ANDROID_APP)

target_link_libraries(byedpi PRIVATE android log)

# 16-килобайтное выравнивание сегментов — требование Android 15+ для
# устройств с page size 16K (без него dlopen падает). На поведение обхода
# не влияет; эталон собирается своим CI, где это обеспечивает toolchain.
target_link_options(byedpi PRIVATE "-Wl,-z,max-page-size=16384")
