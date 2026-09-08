package securemem

// The functions used by the all platforms

// Options configure allocation behavior.
type Option func(*config)

type config struct { lock bool }

// WithLocking attempts to lock the allocated buffer in physical RAM using mlock.
func WithLocking(lock bool) Option {
	return func(c *config) { c.lock = lock }
}

// ZeroBytes explicitly zeroes out sensitive memory slices
func ZeroBytes(b []byte) {
	if b == nil {return}
	for i := range b { b[i] = 0 }
}
