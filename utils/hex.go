package utils

import "encoding/hex"

func HexOctets(data []byte) (result string) {
	for i := 0; i < len(data); i += 8 {
		if len(result) != 0 {
			result += " "
		}
		result += hex.EncodeToString(data[i : i+8])
	}

	return result
}
