package stream

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestUint16FramesUseNetworkByteOrder(t *testing.T) {
	t.Parallel()

	wire := []byte{0, 7, 'm', 'e', 's', 's', 'a', 'g', 'e'}

	for _, test := range []struct {
		name  string
		chunk int
	}{
		{name: "normal writer", chunk: len(wire)},
		{name: "short writes", chunk: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			writer := &shortWriter{chunk: test.chunk}

			err := WriteUint16Frame(writer, []byte("message"))
			if err != nil {
				t.Fatalf("write frame: %v", err)
			}

			if !bytes.Equal(writer.contents, wire) {
				t.Errorf("wire bytes = %v, want %v", writer.contents, wire)
			}
		})
	}

	contents, err := ReadUint16Frame(bytes.NewReader(wire), 32)
	if err != nil || string(contents) != "message" {
		t.Fatalf("read fixed wire frame = %q, %v", contents, err)
	}
}

func TestReadUint16FrameRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "empty", wire: nil},
		{name: "incomplete length", wire: []byte{0}},
		{name: "zero length", wire: []byte{0, 0}},
		{name: "exceeds maximum", wire: []byte{0, 33}},
		{name: "truncated payload", wire: []byte{0, 2, 'x'}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ReadUint16Frame(bytes.NewReader(test.wire), 32)
			if err == nil {
				t.Fatal("invalid frame was accepted")
			}
		})
	}
}

func TestWriteUint16FrameRejectsZeroProgress(t *testing.T) {
	t.Parallel()

	err := WriteUint16Frame(&shortWriter{}, []byte("message"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write error = %v, want ErrShortWrite", err)
	}
}

type shortWriter struct {
	chunk    int
	contents []byte
}

func (writer *shortWriter) Write(contents []byte) (int, error) {
	written := min(writer.chunk, len(contents))
	writer.contents = append(writer.contents, contents[:written]...)

	return written, nil
}
