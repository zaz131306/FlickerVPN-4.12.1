// Package nm — протокол Native Messaging браузера:
// каждое сообщение = 4 байта длины (little-endian) + JSON.
package nm

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxMessageSize — защита от мусорных/битых заголовков длины (4 МБ с запасом).
const MaxMessageSize = 4 * 1024 * 1024

// Message — входящая команда от расширения.
type Message struct {
	Command    string          `json:"command"`
	Config     json.RawMessage `json:"config,omitempty"`
	Server     string          `json:"server,omitempty"`
	Port       int             `json:"port,omitempty"`
	ServerID   string          `json:"serverId,omitempty"`
	URL        string          `json:"url,omitempty"`
	ExtVersion string          `json:"extVersion,omitempty"`
	Text       string          `json:"text,omitempty"`

	// probeServers: пакетная проверка живости серверов (задача 3)
	RequestID string          `json:"requestId,omitempty"`
	Servers   json.RawMessage `json:"servers,omitempty"`
	Opts      json.RawMessage `json:"opts,omitempty"`
}

// ErrTooLarge — заявленная длина сообщения превышает лимит.
var ErrTooLarge = errors.New("nm: message too large")

// Read читает одно NM-сообщение из r (блокирующе).
func Read(r io.Reader) (*Message, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 {
		return nil, errors.New("nm: zero-length message")
	}
	if n > MaxMessageSize {
		return nil, fmt.Errorf("%w: %d", ErrTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var msg Message
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, fmt.Errorf("nm: bad json: %w", err)
	}
	return &msg, nil
}

// Writer — потокобезопасная запись NM-сообщений (stdout делится между
// статусами, статистикой и ответами из разных горутин).
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

func (wr *Writer) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxMessageSize {
		return ErrTooLarge
	}
	wr.mu.Lock()
	defer wr.mu.Unlock()
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := wr.w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = wr.w.Write(b)
	return err
}
