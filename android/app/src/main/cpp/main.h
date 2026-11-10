/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Заголовки byedpi, нужные JNI-обёртке.
 *
 * main() у byedpi объявлен в main.c, но не в собственном заголовке, поэтому
 * объявляем его здесь. clear_params() используется самим byedpi при разборе
 * командной строки и здесь объявлен для полноты (взято из cpp/main.h проекта
 * EwenLoy/ByeByeDPI-x-tg, где эта обёртка проверена на практике).
 */
#ifndef FLICKER_BYEDPI_MAIN_H
#define FLICKER_BYEDPI_MAIN_H

void clear_params(char *line, char **argv);
int main(int argc, char **argv);

#endif /* FLICKER_BYEDPI_MAIN_H */
