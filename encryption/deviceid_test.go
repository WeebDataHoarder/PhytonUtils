package encryption

import (
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/crc"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/utils"
	"slices"
	"testing"
)

var testDeviceId = DeviceId{0x003B0056, 0x4D4B5002, 0x20323455}
var sampleDeviceMangleKeyOffset6 = DeviceMangleKeyOffset6(testDeviceId)

var sampleEncryptedCodeA = []byte{
	0xce, 0xc4, 0xb1, 0x88, 0x85, 0xcb, 0x4f, 0x56, 0x8b, 0x1c, 0xc6, 0x01, 0x00, 0x43, 0x9b, 0x61,
	0x3b, 0xb4, 0x37, 0x37, 0x40, 0xe3, 0x73, 0x96, 0xdd, 0x8e, 0xa2, 0xab, 0x89, 0x51, 0x14, 0xcf,
	0xfe, 0x05, 0x99, 0xee, 0xd6, 0xec, 0xb3, 0x69, 0xce, 0x57, 0xe4, 0xc3, 0xd9, 0xea, 0x18, 0x35,
	0x2c, 0x64, 0xee, 0x2e, 0x77, 0x98, 0xc5, 0x63, 0x24, 0xf9, 0xf3, 0x29, 0x09, 0x57, 0xef, 0x14,
	0x2e, 0xa7, 0x76, 0x3e, 0x7a, 0x3d, 0x8b, 0x7c, 0xc4, 0xe7, 0x49, 0x87, 0x2f, 0x6c, 0x36, 0x30,
	0xb2, 0x2b, 0x81, 0x8e, 0x67, 0x04, 0xbb, 0x7b, 0x67, 0xac, 0x8d, 0x12, 0x72, 0xac, 0x52, 0xcf,
	0xf3, 0xcc, 0xd1, 0x4c, 0x64, 0x88, 0x17, 0xdf, 0x04, 0x2e, 0x86, 0xa9, 0x5e, 0xca, 0x1b, 0xf4,
	0xd3, 0xa7, 0xdd, 0x87, 0x83, 0x9a, 0x36, 0x02, 0x82, 0xef, 0xac, 0xaa, 0xae, 0x62, 0x2a, 0xec,
	0x20, 0x84, 0xe4, 0xc7, 0x06, 0xa7, 0x2b, 0x88, 0x76, 0xd6, 0xd4, 0x6b, 0xfa, 0xdd, 0xfb, 0x76,
	0xe3, 0x56, 0xf2, 0xeb, 0x7b, 0x0e, 0x55, 0x09, 0x42, 0x57, 0xe5, 0xf8, 0x6d, 0x64, 0x23, 0x3f,
	0x92, 0x01, 0xd7, 0x1d, 0x5f, 0x45, 0xb9, 0x04, 0xca, 0x6f, 0x17, 0xd8, 0x0d, 0x1d, 0x7f, 0x14,
	0xb7, 0xf3, 0x02, 0x42, 0x90, 0x2a, 0x99, 0x32, 0xf5, 0xe6, 0x1d, 0xf6, 0x8f, 0xab, 0xd8, 0x45,
	0xde, 0x4b, 0x0b, 0x0a, 0x58, 0x5d, 0x74, 0xdf, 0x13, 0x43, 0x88, 0xdd, 0xdb, 0xb3, 0xdc, 0x7a,
	0x94, 0xb9, 0xfb, 0x21, 0x44, 0xd7, 0x86, 0x08, 0xc4, 0xdb, 0x1f, 0x64, 0x8f, 0x73, 0x11, 0x0e,
	0xf7, 0x65, 0x92, 0x0a, 0xa5, 0x43, 0x70, 0xf7, 0xba, 0x38, 0xeb, 0x1f, 0x6b, 0x19, 0x66, 0x79,
	0x43, 0x80, 0x4e, 0xbb, 0x9e, 0x7b, 0x96, 0x61, 0x86, 0x72, 0xb4, 0xfe, 0xba, 0x14, 0xfa, 0xbd,
	0x9f, 0x0b, 0x2a, 0x3c, 0x06, 0x9c, 0xfa, 0x9e, 0x93, 0x9f, 0x92, 0xc1, 0x09, 0x69, 0x0d, 0x94,
}

var terminator1 = []byte{0xc7, 0x5f, 0x36, 0x28, 0xd6, 0x08, 0xad, 0x1b}

var sampleEncryptedCodeB = []byte{
	0x55, 0x62, 0x55, 0x07, 0x46, 0x8d, 0xa2, 0xdd, 0xed, 0xa5, 0xda, 0x56, 0xbd, 0x35, 0x4d, 0x86,
	0x65, 0x7b, 0xd1, 0x31, 0xc4, 0x31, 0xa2, 0x43, 0xa1, 0x91, 0x5f, 0xf7, 0x21, 0x2d, 0xbf, 0x21,
	0x4f, 0x59, 0xd1, 0x4e, 0xa7, 0x99, 0xc3, 0xcc, 0x28, 0x46, 0x7f, 0x68, 0xbc, 0xe2, 0x1b, 0x12,
	0x12, 0xea, 0xb1, 0xf9, 0x7b, 0xb9, 0x44, 0x7d, 0x91, 0xab, 0xbe, 0xc7, 0xb1, 0x03, 0x15, 0xe4,
	0x79, 0x09, 0xaa, 0xdc, 0x0e, 0x75, 0xdf, 0x4d, 0xe0, 0xc9, 0x26, 0xe0, 0x47, 0xb6, 0x81, 0xfa,
	0xba, 0x80, 0xa0, 0x37, 0xcd, 0xde, 0x7a, 0x4b, 0x1f, 0x89, 0x2f, 0x01, 0x76, 0x2e, 0x0b, 0xcc,
	0x55, 0xc2, 0xfc, 0xbe, 0xfc, 0xbd, 0x53, 0xf1, 0x6d, 0x7a, 0xf5, 0x2e, 0xc7, 0x63, 0x01, 0x66,
	0xf9, 0xe8, 0xbc, 0x20, 0x50, 0x7c, 0xde, 0x06, 0x37, 0xad, 0x9b, 0xf0, 0xca, 0x76, 0x8b, 0x3f,
	0x4a, 0xe8, 0xbf, 0x5f, 0x99, 0xf5, 0x9a, 0x7f, 0x1b, 0x9a, 0x72, 0x8b, 0x4a, 0x5f, 0x29, 0x09,
	0x86, 0x72, 0xb4, 0xfe, 0xba, 0x14, 0xfa, 0xbd, 0xde, 0xe4, 0xa3, 0x70, 0x96, 0xee, 0xe4, 0x0f,
}

var terminator2 = []byte{0x31, 0xa2, 0x8b, 0xe6, 0xfc, 0x3e, 0xd0, 0x94}

func TestDecryptDeviceCode_A(t *testing.T) {
	t.Parallel()

	code := slices.Clone(sampleEncryptedCodeA)

	DecryptDeviceCode(testDeviceId, code)

	for i := 0; i < len(code); i += 16 {
		t.Logf("%s", utils.HexOctets(code[i:min(len(code), i+16)]))
	}

	const expectedCRC = 0x39f8c16e
	crcValue := crc.CalculateCRC(code)

	if crcValue != expectedCRC {
		t.Fatalf("expected CRC %08x, got %08x", expectedCRC, crcValue)
	}
}

func TestDecryptDeviceCode_B(t *testing.T) {
	t.Parallel()

	code := slices.Clone(sampleEncryptedCodeB)

	DecryptDeviceCode(testDeviceId, code)

	for i := 0; i < len(code); i += 16 {
		t.Logf("%s", utils.HexOctets(code[i:min(len(code), i+16)]))
	}

	const expectedCRC = 0x475f4cc9
	crcValue := crc.CalculateCRC(code)

	if crcValue != expectedCRC {
		t.Fatalf("expected CRC %08x, got %08x", expectedCRC, crcValue)
	}
}