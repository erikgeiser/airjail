package stream

import (
	"bytes"
	"io"
	"testing"
)

func TestUint16FrameRoundTrip(t *testing.T) {
	t.Parallel()

	var framed bytes.Buffer

	err := WriteUint16Frame(&framed, []byte("message"))
	if err != nil {
		t.Fatalf("WriteUint16Frame: %v", err)
	}

	contents, err := ReadUint16Frame(&framed, 32)
	if err != nil {
		t.Fatalf("ReadUint16Frame: %v", err)
	}

	if string(contents) != "message" {
		t.Errorf("contents = %q, want message", contents)
	}
}

func TestWriteUint16FrameHandlesShortWrites(t *testing.T) {
	t.Parallel()

	writer := &shortWriter{}

	err := WriteUint16Frame(writer, []byte("message"))
	if err != nil {
		t.Fatalf("WriteUint16Frame: %v", err)
	}

	contents, err := ReadUint16Frame(bytes.NewReader(writer.contents), 32)
	if err != nil {
		t.Fatalf("ReadUint16Frame: %v", err)
	}

	if string(contents) != "message" {
		t.Errorf("contents = %q, want message", contents)
	}
}

type shortWriter struct {
	contents []byte
}

func (writer *shortWriter) Write(contents []byte) (int, error) {
	if len(contents) == 0 {
		return 0, io.ErrShortWrite
	}

	writer.contents = append(writer.contents, contents[0])

	return 1, nil
}
