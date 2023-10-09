package encryption

// JavaRandMultiplier 25214903917
const JavaRandMultiplier uint64 = 0x5DEECE66D

const JavaRandAddend uint64 = 11

const JavaRandOutputShift = 48 - 16
const JavaRandOutputMask uint64 = 0xFFFF

const JavaRandModulus = (1 << 48) - 1

// JavaRandMultiplierInverse Calculated using math.ModularMultiplicativeInverseBits(uint64(JavaRandMultiplier), 48)
const JavaRandMultiplierInverse uint64 = 0xdfe05bcb1365

// JavaRand Borland java.util.Random
func JavaRand(seed uint64) (newSeed uint64, output uint16) {
	newSeed = JavaRandNextSeed(seed)
	return newSeed, JavaRandOutput(newSeed)
}

func JavaRandOutput(seed uint64) uint16 {
	return uint16(seed >> JavaRandOutputShift)
}

func JavaRandOutputBits(seed uint64, bits int) uint64 {
	return seed >> (48 - bits)
}

func JavaRandNextSeed(seed uint64) uint64 {
	return (seed*JavaRandMultiplier + JavaRandAddend) & JavaRandModulus
}

func JavaRandPreviousSeed(seed uint64) uint64 {
	return ((seed - JavaRandAddend) * JavaRandMultiplierInverse) & JavaRandModulus
}
