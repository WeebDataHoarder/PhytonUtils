package encryption

func DecryptFirmwareData(buf []byte, readAddressSize bool) {
	//TODO
	seed := uint32(0x2009)

	var blockBuf [8]byte
	for i := 0; i < len(buf); i += 8 {
		copy(blockBuf[:], buf[i:])
		seed = BorlandRandXORInPlace(blockBuf[:], seed)
	}
}
