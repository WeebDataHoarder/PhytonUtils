package encryption

import "encoding/binary"

type DeviceId [3]uint32

func DeviceMangleKeyOffset6(deviceId DeviceId) *MangleKeyData {
	var d MangleKeyData
	outerKey := HardcodedMangleTable[OuterMangleKeyOffsetDeviceId]
	binary.LittleEndian.PutUint32(d[:], deviceId[0]^outerKey.RoundKey(0))
	binary.LittleEndian.PutUint32(d[4:], deviceId[1]^outerKey.RoundKey(1))
	binary.LittleEndian.PutUint32(d[8:], deviceId[2]^outerKey.RoundKey(2))
	binary.LittleEndian.PutUint32(d[12:], outerKey.RoundKey(3))

	return &d
}

func DeviceMangleKeyOffset0(deviceId DeviceId) *MangleKeyData {
	var d MangleKeyData
	outerKey := HardcodedMangleTable[OuterMangleKeyOffsetDefault]
	binary.LittleEndian.PutUint32(d[:], deviceId[0]^outerKey.RoundKey(0))
	binary.LittleEndian.PutUint32(d[4:], deviceId[1]^outerKey.RoundKey(1))
	binary.LittleEndian.PutUint32(d[8:], deviceId[2]^outerKey.RoundKey(2))
	binary.LittleEndian.PutUint32(d[12:], (^deviceId[0])^outerKey.RoundKey(3))

	return &d
}

// DecryptDeviceCode Decrypts code specifically encrypted to only work on a specific device id
func DecryptDeviceCode(deviceId DeviceId, code []byte) []byte {
	if len(code)%8 != 0 {
		panic("len must be % 8")
	}
	DeviceMangleKeyOffset0(deviceId).Decrypt(code)

	return code
}

// EncryptDeviceCode Encrypt code specifically encrypted to only work on a specific device id
func EncryptDeviceCode(deviceId DeviceId, code []byte) []byte {
	if len(code)%8 != 0 {
		panic("len must be % 8")
	}
	DeviceMangleKeyOffset0(deviceId).Encrypt(code)

	return code
}
