package stream

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// ReadUint16Frame reads one two-byte big-endian length-prefixed frame.
func ReadUint16Frame(reader io.Reader, maximum int) ([]byte, error) {
	if maximum < 1 || maximum > math.MaxUint16 {
		return nil, fmt.Errorf("frame maximum must be from 1 through %d", math.MaxUint16)
	}

	lengthBytes := make([]byte, 2)

	_, err := io.ReadFull(reader, lengthBytes)
	if err != nil {
		return nil, err
	}

	length := int(binary.BigEndian.Uint16(lengthBytes))
	if length == 0 || length > maximum {
		return nil, fmt.Errorf("frame length %d is invalid", length)
	}

	contents := make([]byte, length)

	_, err = io.ReadFull(reader, contents)
	if err != nil {
		return nil, fmt.Errorf("read frame contents: %w", err)
	}

	return contents, nil
}

// WriteUint16Frame writes one two-byte big-endian length-prefixed frame.
func WriteUint16Frame(writer io.Writer, contents []byte) error {
	if len(contents) == 0 || len(contents) > math.MaxUint16 {
		return fmt.Errorf("frame length %d is invalid", len(contents))
	}

	frame := make([]byte, 2, 2+len(contents))
	binary.BigEndian.PutUint16(frame, uint16(len(contents)))
	frame = append(frame, contents...)

	for len(frame) != 0 {
		written, err := writer.Write(frame)
		if err != nil {
			return err
		}

		if written == 0 {
			return io.ErrShortWrite
		}

		frame = frame[written:]
	}

	return nil
}
