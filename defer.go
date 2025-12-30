package caddy_oidc

import (
	"context"
)

// DeferredResult represents a computation that runs in the background.
type DeferredResult[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// Defer starts the provided function in a separate goroutine and returns a handle to the result.
func Defer[T any](fn func() (T, error)) *DeferredResult[T] {
	d := &DeferredResult[T]{
		done: make(chan struct{}),
	}

	go func() {
		d.value, d.err = fn()
		close(d.done)
	}()

	return d
}

// Get blocks until the background process is finished or the context is canceled.
func (d *DeferredResult[T]) Get(ctx context.Context) (T, error) {
	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case <-d.done:
		return d.value, d.err
	}
}
