package crc

var CRCTable = func() [256]uint32 {
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
		table[i] = uint32(polynomialDivision(0x04C11DB7, uint64(i), 32))
	}
	return table
}()

type CRC struct {
	crc uint32
}

func NewCRC() *CRC {
	return &CRC{
		crc: 0xFFFFFFFF,
	}
}

func (c *CRC) Update(buf []byte) {
	const chunkSize = 4
	remainder := len(buf) % chunkSize
	chunks := len(buf) / chunkSize

	for chunksLeft := chunks; chunksLeft > 0; chunksLeft-- {
		index := (chunks - chunksLeft) * chunkSize
		c.crc = CRCTable[((buf[index+3]&255)^byte(c.crc>>24))] ^ (c.crc << 8)
		c.crc = CRCTable[((buf[index+2]&255)^byte(c.crc>>24))] ^ (c.crc << 8)
		c.crc = CRCTable[((buf[index+1]&255)^byte(c.crc>>24))] ^ (c.crc << 8)
		c.crc = CRCTable[((buf[index]&255)^byte(c.crc>>24))] ^ (c.crc << 8)
	}

	if remainder != 0 {
		var paddingBuffer [chunkSize]byte
		copy(paddingBuffer[:], buf[chunks*chunkSize:])
		c.Update(paddingBuffer[:])
	}
}

func (c *CRC) Sum32() uint32 {
	return c.crc
}

func CalculateCRC(buf []byte) uint32 {
	crc := NewCRC()
	crc.Update(buf)
	return crc.Sum32()
}
