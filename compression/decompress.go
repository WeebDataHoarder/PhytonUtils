package compression

import (
	"bytes"
	"errors"
	"github.com/icza/bitio"
)

func FirmwareBlockDecompress(data []byte) (output []byte, err error) {

	windowIndex := WindowInitialIndex

	output = make([]byte, 0, DataMaxSize)

	window := CreateWindow()

	windowBuffer := make([]byte, len(window))

	r := bitio.NewReader(bytes.NewReader(data))

	var buf []byte
	var isLiteral bool
	var length, literal, offsetIndex uint64
	for {

		if isLiteral, err = r.ReadBool(); err != nil {
			break
		}

		if !isLiteral {
			if offsetIndex, err = r.ReadBits(OffsetBits); err != nil {
				break
			} else if length, err = r.ReadBits(LengthBits); err != nil {
				return nil, err
			} else if length += MaxUncoded; DataMaxSize < (length + uint64(len(output))) {
				return nil, errors.New("out of bounds output")
			}

			windowIndex, buf = window.GetSet(int(offsetIndex), windowIndex, int(length), windowBuffer)
			output = append(output, buf...)
		} else {
			if literal, err = r.ReadBits(LiteralBits); err != nil {
				break
			} else if (DataMaxSize - 1) < len(output) {
				return nil, errors.New("out of bounds output")
			}

			output = append(output, byte(literal))
			windowIndex = window.SetByte(windowIndex, byte(literal))
		}
	}

	return output, nil
}
