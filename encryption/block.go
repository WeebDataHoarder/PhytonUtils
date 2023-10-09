package encryption

import (
	"encoding/binary"
	"errors"
	"fmt"
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

func (b EncryptedBlock) generateKeyBlock(material KeyMaterial) (mangleIndex uint32) {
	_ = b[EncryptedBlockKeySize-1]

	var crcValue uint32
	if material.CRC != nil {
		crcValue = material.CRC(b.DataBlock())
	} else {
		crcValue = crc.CalculateCRC(b.DataBlock())
	}

	binary.LittleEndian.PutUint32(b[EncryptedBlockCRC1Offset:], crcValue)
	binary.LittleEndian.PutUint32(b[EncryptedBlockCRC2Offset:], crcValue)

	material.Generator.FillKeyBlock(b[EncryptedBlockMangleKeyOffset:EncryptedBlockCRC1Offset])
	material.Generator.FillKeyBlock(b[EncryptedBlockPaddingKeyOffset:EncryptedBlockKeySize])

	return material.Generator.MangleIndex()
}

const (
	MangleIndexNormalKey0 = iota
	MangleIndexNormalKey1
	MangleIndexNormalKey2
	MangleIndexNormalKey3
	MangleIndexNormalKey4
	MangleIndexNormalKey5
	MangleIndexNormalKey6
	MangleIndexNormalKey7

	MangleIndexAlternateKey0
	MangleIndexAlternateKey1
	MangleIndexAlternateKey2
	MangleIndexAlternateKey3
	MangleIndexAlternateKey4
	MangleIndexAlternateKey5
	MangleIndexAlternateKey6
	MangleIndexAlternateKey7

	MangleIndexDeviceKey = 0xffff
)

func (b EncryptedBlock) Encrypt(material KeyMaterial) error {

	mangleIndex := b.generateKeyBlock(material)

	// Mangle of data
	b.MangleKey().Encrypt(b.DataBlock())

	var keyData MangleKeyData

	// Inner mangle of key
	if mangleIndex <= MangleIndexNormalKey7 {
		keyData = HardcodedMangleTable[mangleIndex]
	} else if mangleIndex <= MangleIndexAlternateKey7 {
		if material.AlternateKeyTable == nil {
			keyData = AlternateMangleTable[mangleIndex-MangleIndexAlternateKey0]
		} else {
			keyData = material.AlternateKeyTable[mangleIndex-MangleIndexAlternateKey0]
		}
	} else {
		if mangleIndex != MangleIndexDeviceKey {
			return errors.New("invalid key number")
		}

		if material.DeviceKey == nil {
			return errors.New("unsupported device key")
		}

		keyData = *material.DeviceKey
	}

	keyData.Encrypt(b.MangleKeyBlock())

	binary.LittleEndian.PutUint16(b[EncryptedBlockMangleIndexOffset:], uint16(mangleIndex))

	// Outer mangle of key
	HardcodedMangleTable[material.OuterKeyOffset].Encrypt(b.KeyBlock())

	return nil
}

func (b EncryptedBlock) Decrypt(material KeyMaterial, verifyCrc bool) (err error) {
	// Outer unmangle of key
	HardcodedMangleTable[material.OuterKeyOffset].Decrypt(b.KeyBlock())

	mangleIndex := b.MangleIndex()

	var keyData MangleKeyData
	if mangleIndex <= MangleIndexNormalKey7 {
		keyData = HardcodedMangleTable[mangleIndex]
	} else if mangleIndex <= MangleIndexAlternateKey7 {
		if material.AlternateKeyTable == nil {
			keyData = AlternateMangleTable[mangleIndex-MangleIndexAlternateKey0]
		} else {
			keyData = material.AlternateKeyTable[mangleIndex-MangleIndexAlternateKey0]
		}
	} else {
		if mangleIndex != MangleIndexDeviceKey {
			return errors.New("invalid key number")
		}

		if material.DeviceKey == nil {
			return errors.New("unsupported device key")
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
		var calculatedCrc uint32
		if material.CRC != nil {
			calculatedCrc = material.CRC(b.DataBlock())
		} else {
			calculatedCrc = crc.CalculateCRC(b.DataBlock())
		}

		if calculatedCrc != crc1 {
			return fmt.Errorf("data CRC not matching: expected %08x, got %08x", crc1, calculatedCrc)
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
