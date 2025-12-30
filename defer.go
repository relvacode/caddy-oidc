package caddy_oidc

import "sync"

func Defer[T any](f func() (T, error)) *Deferred[T] {
	var df = &Deferred[T]{mu: new(sync.RWMutex)}
	df.mu.Lock()

	go func() {
		df.v, df.err = f()
		df.mu.Unlock()
	}()

	return df
}

// Deferred holds a write lock on an internal mutex until a deferred function completes.
// Once the function completes, the value and error are set and the lock is released.
type Deferred[T any] struct {
	mu  *sync.RWMutex
	v   T
	err error
}

func (d *Deferred[T]) Get() (T, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.v, d.err
}
