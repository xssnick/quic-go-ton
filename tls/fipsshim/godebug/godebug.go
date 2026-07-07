// Package godebug is a minimal stand-in for the standard library's
// internal/godebug, used by the vendored crypto/tls fork.
//
// The fork only consults GODEBUG settings to toggle legacy/no-longer-default
// behaviors (3DES, RSA key exchange, MLKEM, unsafe EKM, ...). For this fork we
// always take the modern default path, so every setting reports the empty
// value and non-default counters are no-ops.
package godebug

// Setting mirrors the subset of *godebug.Setting used by crypto/tls.
type Setting struct {
	name string
}

// New returns a Setting for the named GODEBUG key.
func New(name string) *Setting { return &Setting{name: name} }

// Name returns the setting name.
func (s *Setting) Name() string { return s.name }

// Value always returns "" so the fork uses its compiled-in defaults.
func (s *Setting) Value() string { return "" }

// IncNonDefault is a no-op; the fork has no telemetry to record.
func (s *Setting) IncNonDefault() {}
