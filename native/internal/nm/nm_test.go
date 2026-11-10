package nm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(b)))
	out.Write(lenBuf)
	out.Write(b)
	return out.Bytes()
}

func TestReadRoundTrip(t *testing.T) {
	raw := encode(t, Message{Command: "start", ServerID: "nl1", Port: 443})
	msg, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command != "start" || msg.ServerID != "nl1" || msg.Port != 443 {
		t.Fatalf("bad message: %+v", msg)
	}
}

func TestReadPartialThenEOF(t *testing.T) {
	raw := encode(t, Message{Command: "stop"})
	if _, err := Read(bytes.NewReader(raw[:len(raw)-2])); err != io.ErrUnexpectedEOF {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadRejectsHugeLength(t *testing.T) {
	var buf bytes.Buffer
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, MaxMessageSize+1)
	buf.Write(lenBuf)
	if _, err := Read(&buf); err == nil {
		t.Fatal("expected error for oversized length")
	}
}

func TestReadRejectsBadJSON(t *testing.T) {
	var buf bytes.Buffer
	lenBuf := make([]byte, 4)
	payload := []byte("{not json")
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(payload)))
	buf.Write(lenBuf)
	buf.Write(payload)
	if _, err := Read(&buf); err == nil {
		t.Fatal("expected json error")
	}
}

func TestWriterFraming(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.Write(map[string]any{"type": "status", "status": "connected"}); err != nil {
		t.Fatal(err)
	}
	msg, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command != "" {
		t.Fatalf("unexpected command: %q", msg.Command)
	}
	// проверим, что raw-поле type/status дошло (Message его не несёт — декодируем вручную)
	var generic map[string]any
	raw := buf.Bytes()
	n := binary.LittleEndian.Uint32(raw[:4])
	if err := json.Unmarshal(raw[4:4+n], &generic); err != nil {
		t.Fatal(err)
	}
	if generic["type"] != "status" || generic["status"] != "connected" {
		t.Fatalf("bad payload: %v", generic)
	}
}

func TestWriterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func() {
			_ = w.Write(map[string]any{"type": "stats"})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 32; i++ {
		<-done
	}
	// буфер должен разбираться как последовательность валидных сообщений
	r := bytes.NewReader(buf.Bytes())
	for i := 0; i < 32; i++ {
		if _, err := Read(r); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
}
