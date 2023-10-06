package compression

import (
	"bytes"
	"errors"
	"github.com/icza/bitio"
)

func FirmwareBlockCompress(data []byte, exhaustive bool) (output []byte, err error) {
	if len(data) == 0 {
		return nil, nil
	}

	if len(data) > DataMaxSize {
		return nil, errors.New("out of bounds input")
	}

	windowIndex := WindowInitialIndex

	window := CreateWindow()

	outputBuffer := bytes.NewBuffer(make([]byte, 0, DataMaxSize))
	w := bitio.NewWriter(outputBuffer)

	for len(data) > 0 {
		// Find maximum pattern in window

		offsetIndex, length := window.Find(windowIndex, data, exhaustive)

		if offsetIndex != -1 {
			// write false for not encoding a literal
			if err = w.WriteBool(false); err != nil {
				return nil, err
			}
			// write index in table
			if err = w.WriteBits(uint64(offsetIndex), OffsetBits); err != nil {
				return nil, err
			}
			// write size of match
			if err = w.WriteBits(uint64(length-MaxUncoded), LengthBits); err != nil {
				return nil, err
			}

			windowIndex = window.Set(windowIndex, data[:length])
			data = data[length:]
		} else {
			// write true for encoding a literal
			if err = w.WriteBool(true); err != nil {
				return nil, err
			}

			literal := data[0]
			data = data[1:]
			windowIndex = window.SetByte(windowIndex, literal)

			// Write literal value
			if err = w.WriteBits(uint64(literal), LiteralBits); err != nil {
				return nil, err
			}
		}
	}

	if err = w.Close(); err != nil {
		return nil, err
	}

	return outputBuffer.Bytes(), nil
}
