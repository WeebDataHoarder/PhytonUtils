package encryption

import "encoding/binary"

func (d MangleKeyData) Encrypt(data []byte) {
	for i := 0; i < len(data); i += MangleKeyBlockSize {
		binary.LittleEndian.PutUint64(data[i:], d.EncryptBlock(binary.LittleEndian.Uint64(data[i:])))
	}
}

func (d MangleKeyData) EncryptBlock(block uint64) uint64 {
	dataA, dataB := uint32(block), uint32(block>>32)

	for round := int32(0); round < MangleKeyRounds; round++ {
		dataB, dataA = encryptRound(binary.LittleEndian.Uint32(d[(round&3)<<2:]), dataA, dataB, uint32(round))
	}

	return uint64(dataA) | (uint64(dataB) << 32)
}

func encryptRound(roundKey uint32, dataA, dataB, round uint32) (uint32, uint32) {
	dataA = round + roundKey + ((dataB >> 8) ^ (dataB << 6)) + dataB + dataA
	return dataA, dataB
}

func (d MangleKeyData) Decrypt(data []byte) {
	for i := 0; i < len(data); i += MangleKeyBlockSize {
		binary.LittleEndian.PutUint64(data[i:], d.DecryptBlock(binary.LittleEndian.Uint64(data[i:])))
	}
}

func (d MangleKeyData) DecryptBlock(block uint64) uint64 {
	dataA, dataB := uint32(block), uint32(block>>32)

	for round := int32(MangleKeyRounds - 1); round != -1; round-- {
		dataA, dataB = decryptRound(binary.LittleEndian.Uint32(d[(round&3)<<2:]), dataB, dataA, uint32(round))
	}

	return uint64(dataA) | (uint64(dataB) << 32)
}

func decryptRound(roundKey uint32, dataA, dataB, round uint32) (uint32, uint32) {
	dataA = (dataA - dataB) - ((dataB >> 8) ^ (dataB << 6)) - roundKey - round
	return dataA, dataB
}
