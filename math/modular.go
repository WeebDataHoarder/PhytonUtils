package math

func ModularMultiplicativeInverse(number, modulo uint64) uint64 {
	for x := uint64(1); x < modulo && x != 0; x++ {
		if ((number%modulo)*(x%modulo))%modulo == 1 {
			return x
		}
	}

	return 0
}

func ModularMultiplicativeInverseBits(number uint64, bits int) uint64 {
	modulo := (uint64(1) << bits) - 1
	for x := uint64(1); x < modulo && x != 0; x++ {
		if ((number&modulo)*(x&modulo))&modulo == 1 {
			return x
		}
	}

	return 0
}

func ModularMultiplicativeInverseFixed[T ~int32 | ~uint32 | ~int64 | ~uint64](number T) T {
	var modulo T
	modulo--

	var one T
	one++

	for x := one; x < modulo && x != 0; x++ {
		if number*x == 1 {
			return x
		}
	}

	return 0
}
