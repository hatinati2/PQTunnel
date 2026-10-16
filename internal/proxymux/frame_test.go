package proxymux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	tests := []Frame{
		{Type: TypeOpenDirect, StreamID: 1, Payload: []byte("example.com:443")},
		{Type: TypeOpenReverse, StreamID: 2, Payload: []byte("web")},
		{Type: TypeOpenOK, StreamID: 1},
		{Type: TypeOpenError, StreamID: 2, Payload: []byte("denied")},
		{Type: TypeData, StreamID: 1, Payload: []byte{0, 1, 2, 3, 255}},
		{Type: TypeClose, StreamID: 2},
		{Type: TypePing, Payload: []byte("nonce")},
		{Type: TypePong, Payload: []byte("nonce")},
	}

	for _, want := range tests {
		t.Run(want.Type.String(), func(t *testing.T) {
			var wire bytes.Buffer
			if err := WriteFrame(&wire, want); err != nil {
				t.Fatalf("WriteFrame() error = %v", err)
			}
			got, err := ReadFrame(&wire)
			if err != nil {
				t.Fatalf("ReadFrame() error = %v", err)
			}
			if got.Type != want.Type || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
				t.Fatalf("round trip mismatch: got %#v, want %#v", got, want)
			}
			if wire.Len() != 0 {
				t.Fatalf("left %d unread bytes", wire.Len())
			}
		})
	}
}

func (typ Type) String() string {
	switch typ {
	case TypeOpenDirect:
		return "open-direct"
	case TypeOpenReverse:
		return "open-reverse"
	case TypeOpenOK:
		return "open-ok"
	case TypeOpenError:
		return "open-error"
	case TypeData:
		return "data"
	case TypeClose:
		return "close"
	case TypePing:
		return "ping"
	case TypePong:
		return "pong"
	default:
		return "unknown"
	}
}

func rawFrame(version, typ byte, streamID, size uint32, reserved uint16) []byte {
	out := make([]byte, headerSize+int(size))
	out[0] = version
	out[1] = typ
	binary.BigEndian.PutUint16(out[2:4], reserved)
	binary.BigEndian.PutUint32(out[4:8], streamID)
	binary.BigEndian.PutUint32(out[8:12], size)
	return out
}

func TestReadFrameRejectsInvalidHeadersBeforePayloadRead(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "unsupported version", wire: rawFrame(2, byte(TypePing), 0, 0, 0)},
		{name: "reserved bits", wire: rawFrame(Version, byte(TypePing), 0, 0, 1)},
		{name: "unknown type", wire: rawFrame(Version, 99, 0, 0, 0)},
		{name: "stream frame zero ID", wire: rawFrame(Version, byte(TypeData), 0, 0, 0)},
		{name: "control frame nonzero ID", wire: rawFrame(Version, byte(TypePing), 9, 0, 0)},
		{name: "oversized control", wire: rawFrame(Version, byte(TypeOpenDirect), 1, maxControlSize+1, 0)},
		{name: "oversized data", wire: rawFrame(Version, byte(TypeData), 1, maxDataSize+1, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only the fixed header is supplied for oversized frames. The
			// implementation must reject the claimed size without waiting
			// for or allocating the advertised payload.
			wire := tt.wire[:headerSize]
			if _, err := ReadFrame(bytes.NewReader(wire)); err == nil {
				t.Fatal("ReadFrame() unexpectedly accepted invalid header")
			}
		})
	}
}

func TestReadFrameRejectsTruncatedInput(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		if _, err := ReadFrame(bytes.NewReader([]byte{Version})); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadFrame() error = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("payload", func(t *testing.T) {
		wire := rawFrame(Version, byte(TypeData), 1, 3, 0)
		wire = append(wire[:headerSize], 1, 2)
		if _, err := ReadFrame(bytes.NewReader(wire)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadFrame() error = %v, want io.ErrUnexpectedEOF", err)
		}
	})
}

func TestWriteFrameRejectsInvalidFrame(t *testing.T) {
	tests := []Frame{
		{Type: Type(99), StreamID: 1},
		{Type: TypeData, StreamID: 0, Payload: []byte("x")},
		{Type: TypePing, StreamID: 1},
		{Type: TypeOpenDirect, StreamID: 1, Payload: bytes.Repeat([]byte("x"), maxControlSize+1)},
		{Type: TypeData, StreamID: 1, Payload: bytes.Repeat([]byte("x"), maxDataSize+1)},
	}
	for _, frame := range tests {
		var wire bytes.Buffer
		if err := WriteFrame(&wire, frame); err == nil {
			t.Fatalf("WriteFrame(%#v) unexpectedly succeeded", frame.Type)
		}
		if wire.Len() != 0 {
			t.Fatalf("invalid frame wrote %d bytes before rejection", wire.Len())
		}
	}
}

type shortWriter struct {
	limit int
}

func (w shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return len(p), nil
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFrameHandlesShortWriters(t *testing.T) {
	want := Frame{Type: TypeData, StreamID: 1, Payload: []byte("short-write-test")}
	var wire bytes.Buffer
	writer := multiWriter{writers: []io.Writer{shortWriter{limit: 2}, &wire}}
	// The first writer consumes each Write call; use a dedicated writer that
	// forwards only a prefix to avoid depending on Writer behavior.
	_ = writer

	var got bytes.Buffer
	if err := WriteFrame(&got, want); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if err := WriteFrame(shortWriter{limit: 2}, want); err != nil {
		t.Fatalf("WriteFrame() should loop over short writes: %v", err)
	}
	if err := WriteFrame(zeroWriter{}, want); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteFrame() error = %v, want io.ErrShortWrite", err)
	}
}

type multiWriter struct {
	writers []io.Writer
}

func (m multiWriter) Write(p []byte) (int, error) {
	if len(m.writers) == 0 {
		return 0, io.ErrClosedPipe
	}
	return m.writers[0].Write(p)
}
