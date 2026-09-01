// Package stream provides connection ownership, framing, and full-duplex stream relaying.
package stream

import (
	"context"
	"errors"
	"io"
	"net"
)

type closeWriter interface {
	CloseWrite() error
}

// Bidirectional copies both directions until they complete or ctx is canceled.
func Bidirectional(ctx context.Context, left net.Conn, leftReader io.Reader, right net.Conn) error {
	results := make(chan error, 2)
	copyStream := func(destination net.Conn, source io.Reader) {
		_, err := io.Copy(destination, source)

		closeable, ok := destination.(closeWriter)
		if ok {
			closeErr := closeable.CloseWrite()
			if err == nil {
				err = closeErr
			}
		}

		results <- err
	}

	go copyStream(right, leftReader)
	go copyStream(left, right)

	var relayErr error

	canceled := false
	contextDone := ctx.Done()

	for completed := 0; completed < 2; {
		select {
		case err := <-results:
			completed++

			if relayErr == nil && isRelayError(err) {
				relayErr = err
				_ = left.Close()
				_ = right.Close()
			}
		case <-contextDone:
			canceled = true
			contextDone = nil
			_ = left.Close()
			_ = right.Close()
		}
	}

	if relayErr != nil {
		return relayErr
	}

	if canceled {
		return ctx.Err()
	}

	return nil
}

func isRelayError(err error) bool {
	return err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled)
}
