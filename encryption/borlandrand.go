package encryption

import (
	"encoding/binary"
)

// BorlandRandMultiplier 22695477
const BorlandRandMultiplier uint32 = 0x015A4E35

const BorlandRandAddend uint32 = 1

const BorlandRandOutputShift = 16
const BorlandRandOutputMask uint32 = 0x7FFF

const BorlandRandModulus = 0xFFFFFFFF

// BorlandRandMultiplierInverse Calculated using math.ModularMultiplicativeInverseFixed(uint32(BorlandRandMultiplier))
const BorlandRandMultiplierInverse uint32 = 0x2925141D

// BorlandRand Borland C++ rand()
func BorlandRand(seed uint32) (newSeed uint32, output uint16) {
	newSeed = BorlandRandNextSeed(seed)
	return newSeed, BorlandRandOutput(newSeed)
}

func BorlandRandOutput(seed uint32) uint16 {
	return uint16(seed>>BorlandRandOutputShift) & uint16(BorlandRandOutputMask)
}

func BorlandRandNextSeed(seed uint32) uint32 {
	return (seed*BorlandRandMultiplier + BorlandRandAddend) & BorlandRandModulus
}

func BorlandRandPreviousSeed(seed uint32) uint32 {
	return ((seed - BorlandRandAddend) * BorlandRandMultiplierInverse) & BorlandRandModulus
}

func BorlandRandXORBytes(src, dst []byte, seed uint32) (newSeed uint32) {
	_ = dst[len(src)-1]
	var output uint16
	for i := range src {
		seed, output = BorlandRand(seed)
		dst[i] = src[i] ^ byte(output)
	}
	return seed
}

func BorlandRandXORInPlace(data []byte, seed uint32) (newSeed uint32) {
	return BorlandRandXORBytes(data, data, seed)
}

func BorlandRandXORUint32(value, seed uint32) (newValue, newSeed uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	newSeed = BorlandRandXORInPlace(buf[:], seed)
	return binary.LittleEndian.Uint32(buf[:]), newSeed
}
