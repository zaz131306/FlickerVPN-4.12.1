// SPDX-License-Identifier: GPL-3.0-or-later
//go:build android

// libbox_bind.go — «якорь» зависимостей для сборки AAR.
//
// gomobile bind (tools/build-libbox-aar.sh) передаёт два пакета:
// ./mobile и github.com/sagernet/sing-box/experimental/libbox.
// Сам native/mobile libbox НЕ импортирует (общаются они через JNI),
// поэтому без этого файла `go mod tidy` вычистил бы транзитивные
// зависимости libbox из go.sum и gomobile bind упал бы с
// «missing go.sum entry».
//
// Импорт действует только при GOOS=android — на десктопные сборки
// (flicker-host) libbox не попадает.
package mobile

import (
	_ "github.com/sagernet/sing-box/experimental/libbox"
)
