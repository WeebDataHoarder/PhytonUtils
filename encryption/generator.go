package encryption

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

type KeyGenerator interface {
	Fill(data []byte)
	MangleIndex() uint32
}

// SecureRandomKeyGenerator Generates random numbers using the system secure random number generator
type SecureRandomKeyGenerator struct{}

func (g *SecureRandomKeyGenerator) Fill(data []byte) {
	io.ReadFull(rand.Reader, data)
}

func (g *SecureRandomKeyGenerator) MangleIndex() uint32 {
	var buf [1]byte
	io.ReadFull(rand.Reader, buf[:])
	return uint32(buf[0] & 0x7)
}

// BorlandRandKeyGenerator Generates random numbers with its value as current seed
type BorlandRandKeyGenerator uint32

func (g *BorlandRandKeyGenerator) Fill(data []byte) {
	seed := uint32(*g)
	for i := 0; i < len(data); i += 2 {
		seed = BorlandRand(seed)
		binary.LittleEndian.PutUint16(data[i:], uint16((seed<<1)>>0x11))
	}
	*g = BorlandRandKeyGenerator(seed)
}

func (g *BorlandRandKeyGenerator) MangleIndex() uint32 {
	seed := uint32(*g)
	seed = BorlandRand(seed)
	mangleIndex := (seed >> 0x10) & 0x7
	*g = BorlandRandKeyGenerator(seed)

	return mangleIndex
}
