//go:generate go run ntt_amd64_src.go -out ntt_amd64.s -stubs ntt_amd64_stubs.go

package internal

import (
	"golang.org/x/sys/cpu"
)

func (p *Poly) NTT() {
	if cpu.X86.HasAVX2 {
		ntt(
			(*[256]uint32)(p),
		)
	} else {
		p.ntt_generic()
	}
}
