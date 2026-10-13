package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxFrameSize = 65535

var ErrInvalidFrame = errors.New("invalid tunnel frame length")

// Frames use a four-byte network-order length followed by one raw layer-3 IP packet.
func WriteFrame(w io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > MaxFrameSize {
		return ErrInvalidFrame
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(packet)))
	if err := writeAll(w, hdr[:]); err != nil {
		return err
	}
	return writeAll(w, packet)
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameSize {
		return nil, ErrInvalidFrame
	}
	p := make([]byte, int(n))
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
