package crc

import (
	"encoding/binary"
)

const Polynomial uint32 = 0x04C11DB7
const InitialValue CRC = 0xFFFFFFFF

var Table = func(polynomial uint64) [256]uint32 {
	polynomialDivision := func(polynomial, input uint64, len uint) uint64 {
		mask := uint64(1)<<len - 1

		for i := uint(0); i < len; i++ {
			bitOut := input>>(len-1) > 0
			input <<= 1
			if bitOut {
				input ^= polynomial
			}
			input &= mask
		}

		return input
	}
	var table [256]uint32
	for i := 0; i < 256; i++ {
		table[i] = uint32(polynomialDivision(polynomial, uint64(i), 32))
	}
	return table
}(uint64(Polynomial))

type CRC uint32

func NewCRC() CRC {
	return InitialValue
}

func (c *CRC) Update(buf []byte) {
	const chunkSize = 4
	remainder := len(buf) % chunkSize
	chunks := len(buf) / chunkSize

	for chunksLeft := chunks; chunksLeft > 0; chunksLeft-- {
		index := (chunks - chunksLeft) * chunkSize
		c.UpdateUint32(binary.LittleEndian.Uint32(buf[index:]))
	}

	if remainder != 0 {
		var paddingBuffer [chunkSize]byte
		copy(paddingBuffer[:], buf[chunks*chunkSize:])
		c.Update(paddingBuffer[:])
	}
}

func (c *CRC) UpdateUint32(data uint32) {
	crc := uint32(*c)

	crc = Table[(byte(data>>24)^byte(crc>>24))] ^ (crc << 8)
	crc = Table[(byte(data>>16)^byte(crc>>24))] ^ (crc << 8)
	crc = Table[(byte(data>>8)^byte(crc>>24))] ^ (crc << 8)
	crc = Table[(byte(data)^byte(crc>>24))] ^ (crc << 8)

	*c = CRC(crc)
}

func (c *CRC) Sum32() uint32 {
	return uint32(*c)
}

func CalculateCRC(buf []byte) uint32 {
	crc := NewCRC()
	crc.Update(buf)
	return crc.Sum32()
}
