package encryption

import (
	"encoding/binary"
	"errors"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/crc"
)

const EncryptedBlockKeySize = 512

const EncryptedBlockMangleIndexOffset = 0
const EncryptedBlockMangleKeyOffset = EncryptedBlockMangleIndexOffset + 2
const EncryptedBlockCRC1Offset = EncryptedBlockMangleKeyOffset + MangleKeyDataSize
const EncryptedBlockCRC2Offset = EncryptedBlockCRC1Offset + 4
const EncryptedBlockPaddingKeyOffset = EncryptedBlockCRC2Offset + 4

type EncryptedBlock []byte

func (b EncryptedBlock) MangleKey() MangleKeyData {
	_ = b[EncryptedBlockKeySize-1]
	return MangleKeyData(b[EncryptedBlockMangleKeyOffset:EncryptedBlockCRC1Offset])
}

// MangleKeyBlock Includes inner MangleKeyData and CRC1, CRC2
func (b EncryptedBlock) MangleKeyBlock() []byte {
	_ = b[EncryptedBlockKeySize-1]
	return b[EncryptedBlockMangleKeyOffset:EncryptedBlockPaddingKeyOffset]
}

func (b EncryptedBlock) KeyBlock() []byte {
	_ = b[EncryptedBlockKeySize-1]
	return b[:EncryptedBlockKeySize]
}

func (b EncryptedBlock) DataBlock() []byte {
	return b[EncryptedBlockKeySize:]
}

func (b EncryptedBlock) MangleIndex() uint32 {
	_ = b[EncryptedBlockKeySize-1]
	return uint32(binary.LittleEndian.Uint16(b[EncryptedBlockMangleIndexOffset:]))
}

func (b EncryptedBlock) CRC() (crc1, crc2 uint32) {
	_ = b[EncryptedBlockKeySize-1]
	return binary.LittleEndian.Uint32(b[EncryptedBlockCRC1Offset:]), binary.LittleEndian.Uint32(b[EncryptedBlockCRC2Offset:])
}

func (b EncryptedBlock) Reset() {
	clear(b)
}

func (b EncryptedBlock) generateKeyBlock(generator KeyGenerator) (mangleIndex uint32) {
	_ = b[EncryptedBlockKeySize-1]

	crcValue := crc.CalculateCRC(b.DataBlock())

	binary.LittleEndian.PutUint32(b[EncryptedBlockCRC1Offset:], crcValue)
	binary.LittleEndian.PutUint32(b[EncryptedBlockCRC2Offset:], crcValue)

	generator.Fill(b[EncryptedBlockMangleKeyOffset:EncryptedBlockCRC1Offset])
	generator.Fill(b[EncryptedBlockPaddingKeyOffset:EncryptedBlockKeySize])

	return generator.MangleIndex()
}

const (
	mangleIndexNormalKey0 = iota
	mangleIndexNormalKey1
	mangleIndexNormalKey2
	mangleIndexNormalKey3
	mangleIndexNormalKey4
	mangleIndexNormalKey5
	mangleIndexNormalKey6
	mangleIndexNormalKey7

	mangleIndexAlternateKey0
	mangleIndexAlternateKey1
	mangleIndexAlternateKey2
	mangleIndexAlternateKey3
	mangleIndexAlternateKey4
	mangleIndexAlternateKey5
	mangleIndexAlternateKey6
	mangleIndexAlternateKey7

	mangleIndexDeviceKey = 0xffff
)

func (b EncryptedBlock) Encrypt(material KeyMaterial) {

	mangleIndex := b.generateKeyBlock(material.Generator)

	// Mangle of data
	b.MangleKey().Encrypt(b.DataBlock())

	// Inner mangle of key
	if material.AlternateMangleKey != nil {
		material.AlternateMangleKey[mangleIndex].Encrypt(b.MangleKeyBlock())

		binary.LittleEndian.PutUint16(b[EncryptedBlockMangleIndexOffset:], uint16(mangleIndex+mangleIndexAlternateKey0))
	} else if material.DeviceKey != nil {
		material.DeviceKey.Encrypt(b.MangleKeyBlock())

		binary.LittleEndian.PutUint16(b[EncryptedBlockMangleIndexOffset:], mangleIndexDeviceKey)
	} else {
		HardcodedMangleTable[mangleIndex].Encrypt(b.MangleKeyBlock())

		binary.LittleEndian.PutUint16(b[EncryptedBlockMangleIndexOffset:], uint16(mangleIndex))
	}

	// Outer mangle of key
	HardcodedMangleTable[material.OuterKeyOffset].Encrypt(b.KeyBlock())
}

func (b EncryptedBlock) Decrypt(material KeyMaterial, verifyCrc bool) (err error) {
	// Outer unmangle of key
	HardcodedMangleTable[material.OuterKeyOffset].Decrypt(b.KeyBlock())

	mangleIndex := b.MangleIndex()

	var keyData MangleKeyData
	if mangleIndex <= mangleIndexNormalKey7 {
		keyData = HardcodedMangleTable[mangleIndex]
	} else if mangleIndex <= mangleIndexAlternateKey7 {
		if material.AlternateMangleKey != nil {
			keyData = material.AlternateMangleKey[mangleIndex-mangleIndexAlternateKey0]
		} else {
			keyData = AlternateMangleTable[mangleIndex-mangleIndexAlternateKey0]
		}
	} else {
		if mangleIndex != mangleIndexDeviceKey {
			return errors.New("invalid key number")
		}

		if material.DeviceKey == nil {
			return errors.New("unsupported hardware key")
		}

		keyData = *material.DeviceKey
	}

	// Inner unmangle of key + CRC data
	keyData.Decrypt(b.MangleKeyBlock())

	// Unmangle of data
	b.MangleKey().Decrypt(b.DataBlock())

	crc1, crc2 := b.CRC()

	if crc1 != crc2 {
		return errors.New("invalid CRC pair")
	}

	if verifyCrc {
		calculatedCrc := crc.CalculateCRC(b.DataBlock())

		if calculatedCrc != crc1 {
			return errors.New("data CRC invalid")
		}
	}

	return nil
}

func NewEncryptedBlock(size int) EncryptedBlock {
	if size%8 != 0 {
		//TODO: auto adjust
		panic("size must be % 8")
	}
	return make(EncryptedBlock, EncryptedBlockKeySize+size)
}
