package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := []byte{0x45, 1, 2, 3, 4}
	var b bytes.Buffer
	if err := WriteFrame(&b, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMaximumIPv6FrameSize(t *testing.T) {
	want := make([]byte, MaxFrameSize)
	want[0] = 0x60
	var b bytes.Buffer
	if err := WriteFrame(&b, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("max-size frame round-trip changed packet")
	}
}

func TestRejectInvalidLength(t *testing.T) {
	if err := WriteFrame(&bytes.Buffer{}, nil); err != ErrInvalidFrame {
		t.Fatalf("got %v", err)
	}
	_, err := ReadFrame(bytes.NewReader([]byte{0, 1, 0, 200}))
	if err != ErrInvalidFrame {
		t.Fatalf("got %v", err)
	}
}
