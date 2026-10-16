// Package proxymux contains the versioned framing primitives for the optional
// user-space proxy transport. It has no listener, routing, TUN, or firewall code.
package proxymux

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// Version is the on-wire protocol version.
	Version byte = 2

	headerSize = 12
	maxDataSize = 16 * 1024
	maxControlSize = 4 * 1024
)

const (
	closeFlagWrite byte = 1
	closeFlagReset byte = 2
)

// Type identifies a logical-stream or control frame.
type Type byte

const (
	TypeOpenDirect Type = 1 + iota
	TypeOpenReverse
	TypeOpenOK
	TypeOpenError
	TypeData
	TypeClose
	TypePing
	TypePong
	TypeWindowUpdate
)

// Frame is a single frame on the multiplexed TLS byte stream.
// A transport connection must serialize concurrent calls to WriteFrame.
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
	case TypeWindowUpdate:
		return "window-update"
	default:
		return "unknown"
	}
}

type Frame struct {
	Type     Type
	StreamID uint32
	Payload  []byte
}

// ReadFrame reads one complete frame, validates its header and bounds its
// allocation before reading its payload. The caller owns the returned payload.
func ReadFrame(r io.Reader) (Frame, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	if header[0] != Version {
		return Frame{}, fmt.Errorf("proxymux: unsupported protocol version %d", header[0])
	}
	if header[2] != 0 || header[3] != 0 {
		return Frame{}, fmt.Errorf("proxymux: reserved header bits must be zero")
	}

	frame := Frame{
		Type:     Type(header[1]),
		StreamID: binary.BigEndian.Uint32(header[4:8]),
	}
	size := binary.BigEndian.Uint32(header[8:12])
	if err := validateHeader(frame.Type, frame.StreamID, size); err != nil {
		return Frame{}, err
	}
	frame.Payload = make([]byte, int(size))
	if _, err := io.ReadFull(r, frame.Payload); err != nil {
		return Frame{}, fmt.Errorf("proxymux: incomplete frame payload: %w", err)
	}
	if err := validatePayload(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

// WriteFrame writes one validated frame. Callers that share a writer must
// serialize the entire call so headers and payloads from separate frames
// cannot interleave.
func WriteFrame(w io.Writer, frame Frame) error {
	size := uint32(len(frame.Payload))
	if err := validateHeader(frame.Type, frame.StreamID, size); err != nil {
		return err
	}
	if err := validatePayload(frame); err != nil {
		return err
	}
	var header [headerSize]byte
	header[0] = Version
	header[1] = byte(frame.Type)
	binary.BigEndian.PutUint32(header[4:8], frame.StreamID)
	binary.BigEndian.PutUint32(header[8:12], size)
	if err := writeFull(w, header[:]); err != nil {
		return fmt.Errorf("proxymux: write frame header: %w", err)
	}
	if err := writeFull(w, frame.Payload); err != nil {
		return fmt.Errorf("proxymux: write frame payload: %w", err)
	}
	return nil
}

func validateHeader(frameType Type, streamID, size uint32) error {
	switch frameType {
	case TypeOpenDirect, TypeOpenReverse:
		if streamID == 0 {
			return fmt.Errorf("proxymux: stream frame requires a nonzero stream ID")
		}
		if size == 0 || size > maxControlSize {
			return fmt.Errorf("proxymux: open request payload must be between 1 and %d bytes", maxControlSize)
		}
	case TypeOpenOK:
		if streamID == 0 {
			return fmt.Errorf("proxymux: stream frame requires a nonzero stream ID")
		}
		if size != 0 {
			return fmt.Errorf("proxymux: OPEN_OK payload must be empty")
		}
	case TypeOpenError:
		if streamID == 0 {
			return fmt.Errorf("proxymux: stream frame requires a nonzero stream ID")
		}
		if size == 0 || size > maxControlSize {
			return fmt.Errorf("proxymux: OPEN_ERROR payload must be between 1 and %d bytes", maxControlSize)
		}
	case TypeData:
		if streamID == 0 {
			return fmt.Errorf("proxymux: stream frame requires a nonzero stream ID")
		}
		if size == 0 || size > maxDataSize {
			return fmt.Errorf("proxymux: DATA payload must be between 1 and %d bytes", maxDataSize)
		}
	case TypeClose:
		if streamID == 0 {
			return fmt.Errorf("proxymux: stream frame requires a nonzero stream ID")
		}
		if size != 1 {
			return fmt.Errorf("proxymux: CLOSE payload must be exactly one byte")
		}
	case TypeWindowUpdate:
		if streamID == 0 {
			return fmt.Errorf("proxymux: WINDOW_UPDATE requires a nonzero stream ID")
		}
		if size != 4 {
			return fmt.Errorf("proxymux: WINDOW_UPDATE payload must be exactly 4 bytes")
		}
	case TypePing, TypePong:
		if streamID != 0 {
			return fmt.Errorf("proxymux: control frame requires stream ID zero")
		}
		if size != 8 {
			return fmt.Errorf("proxymux: keepalive payload must be exactly 8 bytes")
		}
	default:
		return fmt.Errorf("proxymux: unknown frame type %d", frameType)
	}
	return nil
}

func validatePayload(frame Frame) error {
	if frame.Type == TypeClose {
		if len(frame.Payload) != 1 {
			return fmt.Errorf("proxymux: CLOSE payload must be exactly one byte")
		}
		if frame.Payload[0] != closeFlagWrite && frame.Payload[0] != closeFlagReset {
			return fmt.Errorf("proxymux: invalid CLOSE flag %d", frame.Payload[0])
		}
	}
	if frame.Type == TypeWindowUpdate {
		credit := binary.BigEndian.Uint32(frame.Payload)
		if credit == 0 || credit > uint32(streamReadQueueFrames) {
			return fmt.Errorf("proxymux: WINDOW_UPDATE credit must be between 1 and %d frames", streamReadQueueFrames)
		}
	}
	return nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return fmt.Errorf("invalid write count %d", n)
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
