// dilithium implements the CRYSTALS-Dilithium signature schemes
// as submitted to round2 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round2.pdf
//
// Each of the eight different modes of Dilithium is implemented by a
// subpackge.  For instance, Dilithium III can be found in
//
//  github.com/cloudflare/circl/sign/dilithium/mode3
//
// If your choice for mode is fixed compile-time, use the subpackages.
// This package provides a convenient wrapper around all of the subpackages
// so one can be chosen at runtime.

package dilithium

import (
	"github.com/cloudflare/circl/sign/dilithium/mode"
	"github.com/cloudflare/circl/sign/dilithium/mode1"
	"github.com/cloudflare/circl/sign/dilithium/mode1aes"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode2aes"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode3aes"
	"github.com/cloudflare/circl/sign/dilithium/mode4"
	"github.com/cloudflare/circl/sign/dilithium/mode4aes"
)

var (
	Mode1    = mode1.Mode
	Mode2    = mode2.Mode
	Mode3    = mode3.Mode
	Mode4    = mode4.Mode
	Mode1AES = mode1aes.Mode
	Mode2AES = mode2aes.Mode
	Mode3AES = mode3aes.Mode
	Mode4AES = mode4aes.Mode

	modes = map[string]mode.Mode{
		Mode1.Name():    Mode1,
		Mode2.Name():    Mode2,
		Mode3.Name():    Mode3,
		Mode4.Name():    Mode4,
		Mode1AES.Name(): Mode1AES,
		Mode2AES.Name(): Mode2AES,
		Mode3AES.Name(): Mode3AES,
		Mode4AES.Name(): Mode4AES,
	}
)

// ModeNames returns the list of supported modes.
func ModeNames() []string {
	names := []string{}
	for name := range modes {
		names = append(names, name)
	}
	return names
}

// ModeByName returns the mode with the given name or nil when not supported.
func ModeByName(name string) mode.Mode {
	return modes[name]
}
