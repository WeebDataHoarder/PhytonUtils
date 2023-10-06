package encryption

import (
	"encoding/binary"
)

type KeyMaterial struct {
	// Generator Random source to generate the inline material
	Generator          KeyGenerator
	OuterKeyOffset     OuterMangleKeyOffset
	DeviceKey          *MangleKeyData
	AlternateMangleKey *MangleKeyTable
}

func NewFirmwareKeyMaterial(generator KeyGenerator) KeyMaterial {
	return KeyMaterial{
		Generator:          generator,
		OuterKeyOffset:     OuterMangleKeyOffsetFirmware,
		DeviceKey:          nil,
		AlternateMangleKey: nil,
	}
}

func NewMemoryKeyMaterial(generator KeyGenerator) KeyMaterial {
	return KeyMaterial{
		Generator:          generator,
		OuterKeyOffset:     OuterMangleKeyOffsetMemory,
		DeviceKey:          nil,
		AlternateMangleKey: nil,
	}
}

type OuterMangleKeyOffset int

const (
	OuterMangleKeyOffsetFirmware = 0x00
	OuterMangleKeyOffsetDeviceId = 0x01
	OuterMangleKeyOffsetMemory   = 0x06
)

func DeviceMangleKey(deviceId1, deviceId2, deviceId3 uint32) *MangleKeyData {
	var d MangleKeyData
	outerKey := HardcodedMangleTable[OuterMangleKeyOffsetDeviceId]
	binary.LittleEndian.PutUint32(d[:], deviceId1^outerKey.RoundKey(0))
	binary.LittleEndian.PutUint32(d[4:], deviceId2^outerKey.RoundKey(1))
	binary.LittleEndian.PutUint32(d[8:], deviceId3^outerKey.RoundKey(2))
	binary.LittleEndian.PutUint32(d[12:], outerKey.RoundKey(3))

	return &d
}
