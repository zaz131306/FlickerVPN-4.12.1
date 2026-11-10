# android/app/libs/

Сюда кладётся **flicker-box.aar** — нативное ядро (sing-box libbox + Go-фасад
`native/mobile`), собранное через gomobile под **arm64-v8a и x86_64**
(устройства + эмулятор Android Studio).

Сборка (подробно — `android/BUILD-ANDROID.md`):

```bash
# из корня репозитория, нужны: Go 1.26+, JDK 17, Android NDK 27.2.12479018
./tools/build-libbox-aar.sh
```

или CI: `.github/workflows/android.yml` (артефакт `flicker-box.aar`).

Проверить, что в AAR обе ABI:

```bash
unzip -l android/app/libs/flicker-box.aar | grep 'jni/.*libflickerbox\.so'
#   jni/arm64-v8a/libflickerbox.so
#   jni/x86_64/libflickerbox.so
```

Файл `flicker-box.aar` не коммитится (бинарный, ~40–90 МБ) — без него Gradle
sync упадёт с «Could not find libs/flicker-box.aar»: это ожидаемо, сначала
соберите AAR.

Лицензия: GPL-3.0-or-later (внутри — sing-box, GPL-3.0).
