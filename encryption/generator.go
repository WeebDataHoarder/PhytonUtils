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
	var output uint16
	seed := uint32(*g)
	for i := 0; i < len(data); i += 2 {
		seed, output = BorlandRand(seed)
		binary.LittleEndian.PutUint16(data[i:], output)
	}
	*g = BorlandRandKeyGenerator(seed)
}

func (g *BorlandRandKeyGenerator) MangleIndex() uint32 {
	var output uint16
	seed := uint32(*g)
	seed, output = BorlandRand(seed)
	mangleIndex := uint32(output & 0x7)
	*g = BorlandRandKeyGenerator(seed)

	return mangleIndex
}

// ZeroKeyGenerator Always outputs zero
type ZeroKeyGenerator struct{}

func (g *ZeroKeyGenerator) Fill(data []byte) {
	clear(data)
}

func (g *ZeroKeyGenerator) MangleIndex() uint32 {
	return 0
}

type mangleIndexGeneratorWrapper struct {
	generator   KeyGenerator
	mangleIndex uint32
}

func (w *mangleIndexGeneratorWrapper) Fill(data []byte) {
	w.generator.Fill(data)
}

func (w *mangleIndexGeneratorWrapper) MangleIndex() uint32 {
	return w.mangleIndex
}

func NewMangleIndexGeneratorWrapper(generator KeyGenerator, mangleIndex uint32) KeyGenerator {
	return &mangleIndexGeneratorWrapper{
		generator:   generator,
		mangleIndex: mangleIndex,
	}
}

type mangleIndexOffsetGeneratorWrapper struct {
	generator KeyGenerator
	offset    uint32
}

func (w *mangleIndexOffsetGeneratorWrapper) Fill(data []byte) {
	w.generator.Fill(data)
}

func (w *mangleIndexOffsetGeneratorWrapper) MangleIndex() uint32 {
	return w.generator.MangleIndex() + w.offset
}

func NewMangleIndexOffsetGeneratorWrapper(generator KeyGenerator, offset uint32) KeyGenerator {
	return &mangleIndexOffsetGeneratorWrapper{
		generator: generator,
		offset:    offset,
	}
}
