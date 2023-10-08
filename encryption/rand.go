package encryption

import "encoding/binary"

// BorlandRandMultiplier 22695477
const BorlandRandMultiplier = 0x015A4E35

// BorlandRand Borland C++ rand()
func BorlandRand(seed uint32) (newSeed uint32, output uint16) {
	newSeed = seed*BorlandRandMultiplier + 1
	return newSeed, uint16(newSeed>>16) & 0x7FFF
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
