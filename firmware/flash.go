package firmware

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/buffer"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/encryption"
	"io"
)

const FlashAreaPublicSignature = 0x19601217

type FlashAreaData struct {
	// PublicSignature Should always be FlashAreaPublicSignature
	PublicSignature uint32
	StructLen       uint32
	Data            []byte
}

type FlashAreaData_PublicAPI struct {
	BootSignature       uint32
	ProductSerialNumber [32]byte
	TargetFileName      [32]byte
	ProductName         [64]byte
	CalibrationBP0      uint32
	CalibrationBP290    uint32
	VendorID            uint16
	ProductID           uint16
	ManufacturerName    [32]byte
	TargetID            uint32
	TargetStartTimeout  uint32
}

func (f *FlashAreaData) PublicAPI() *FlashAreaData_PublicAPI {
	var result FlashAreaData_PublicAPI
	err := binary.Read(bytes.NewReader(f.Data), binary.LittleEndian, &result)
	if err != nil {
		return nil
	}
	return &result
}

type FlashArea uint32

const (
	FlashAreaUnknown = FlashArea(iota)
	FlashAreaPublicAPI
)

type FlashStatus uint32

const (
	FlashOK = FlashStatus(iota)
	FlashInvAddr
	FlashWrProt
	FlashNotBlank
	FlashVerify
	FlashErase
	FlashProg
	FlashInitEr
	FlashSignEr
	FlashInvalidCRC
	FlashInvalidKeyNumb
	FlashInvalidSign
	FlashInvalidAreaName
	FlashInvalidTarget
	FlashRdpErr
)

// DecodeReadFlashArea Decodes a result of RD_FLASH_AREA command
func DecodeReadFlashArea(data []byte) (*FlashAreaData, error) {
	buf := buffer.Buffer(data)

	flashStatusInt, err := buf.ReadUint32()
	if err != nil {
		return nil, err
	}

	flashStatus := FlashStatus(flashStatusInt)

	if flashStatus != FlashOK {
		if flashStatus == FlashInvalidAreaName {
			return nil, errors.New("area out of bounds")
		} else if flashStatus == FlashInvalidSign {
			return nil, errors.New("invalid area public signature")
		}
		return nil, fmt.Errorf("invalid flash status %d", flashStatus)
	}

	// random seed is set by device using register TIM6_CNT at 0x40001024
	randomSeed, err := buf.ReadUint32()
	if err != nil {
		return nil, err
	}

	size, err := buf.ReadUint32()
	if err != nil {
		return nil, err
	}

	size, randomSeed = encryption.BorlandRandXORUint32(size, randomSeed)
	if int(size) > len(buf) {
		return nil, io.ErrUnexpectedEOF
	}

	flashData := make(buffer.Buffer, size)
	_, err = buf.Read(flashData)
	if err != nil {
		return nil, err
	}
	randomSeed = encryption.BorlandRandXORInPlace(flashData, randomSeed)

	areaData := &FlashAreaData{}

	areaData.PublicSignature, err = flashData.ReadUint32()
	if err != nil {
		return nil, err
	}
	areaData.StructLen, err = flashData.ReadUint32()
	if err != nil {
		return nil, err
	}
	if int(areaData.StructLen) != (len(flashData) + 8) {
		return nil, io.ErrUnexpectedEOF
	}

	areaData.Data = flashData

	return areaData, nil
}
