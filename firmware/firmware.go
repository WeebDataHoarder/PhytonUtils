package firmware

import (
	"bytes"
	"errors"
	"fmt"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/buffer"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/compression"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/crc"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/encryption"
	"golang.org/x/text/encoding/charmap"
	"io"
	"slices"
)

const SerialNumberSize = 16
const MarkerSize = 8
const MarkerPhyton = "Phyton\x00\x00"
const MarkerAlmaCode = "AlmaCode"

const BaseAddress = 0x8000000

type ASFirmwareHeader struct {
	Description [256]byte
	DateTime    DateTime
	DataSize    uint32
}

func (h ASFirmwareHeader) DescriptionString() string {
	decoder := charmap.Windows1251.NewDecoder()
	buf, err := decoder.Bytes(zeroTerminatedSlice(h.Description[:]))
	if err != nil {
		return ""
	}
	return string(buf)
}

func zeroTerminatedSlice(data []byte) []byte {
	return data[:max(0, slices.Index(data, 0))]
}

type ASFileHeader struct {
	Marker       [MarkerSize]byte
	HeaderSize   uint32
	DateTime     DateTime
	BufferSize   uint32
	SerialNumber [SerialNumberSize]byte
	VersionLow   uint8
	VersionHigh  uint8

	// FileCount only available when IsAlmaCode() == true
	FileCount          uint32
	FirmwareHeaderSize uint32
	Compressed         uint8
	Reserved           uint8
	CRC32              uint32
	UpdateCRC32        uint32
}

func (h ASFileHeader) IsAlmaCode() bool {
	return bytes.Compare(h.Marker[:], []byte(MarkerAlmaCode)) == 0
}

type ASBlockHeader struct {
	HeaderSize uint32
	Size       uint32
	Addr       uint32

	SizeAligned uint32
}

type Block struct {
	Header ASBlockHeader
	Block  encryption.EncryptedBlock
}

type Entry struct {
	Header     ASFirmwareHeader
	Blocks     Blocks
	compressed bool
}

func (entry Entry) Code() []byte {
	// Runs https://www.st.com/en/microcontrollers-microprocessors/stm32l475vc.html
	// https://youtu.be/-IsAlSwFWIA?t=508
	var buf []byte
	for _, b := range entry.Blocks {
		decBlock := slices.Clone(b.Block)

		err := decBlock.Decrypt(encryption.NewFlashKeyMaterial(nil), !entry.compressed)
		if err != nil {
			panic(err)
		}
		if entry.compressed {
			data, err := compression.FirmwareBlockDecompress(decBlock.DataBlock()[:b.Header.Size])
			if err != nil {
				panic(err)
			}

			calculatedCrc := crc.CalculateCRC(data)

			crc1, _ := decBlock.CRC()

			if calculatedCrc != crc1 {
				panic("wrong CRC")
			}

			newLength := int(b.Header.Addr) - BaseAddress + len(data)
			if len(buf) < newLength {
				buf = append(buf, make([]byte, newLength-len(buf))...)
			}

			copy(buf[int(b.Header.Addr)-BaseAddress:], data)
		} else {
			newLength := int(b.Header.Addr) - BaseAddress + len(decBlock.DataBlock())
			if len(buf) < newLength {
				buf = append(buf, make([]byte, newLength-len(buf))...)
			}

			copy(buf[int(b.Header.Addr)-BaseAddress:], decBlock.DataBlock())
		}
	}

	return buf
}

type Firmware struct {
	FileHeader ASFileHeader

	Entries []Entry

	Data []byte
}

type Blocks []Block

func BlocksFromData(data []byte) (result Blocks) {
	inputData := buffer.PanicBuffer(data)

	for len(inputData) > 0 {
		var blockHeader ASBlockHeader
		blockHeader.HeaderSize = inputData.ReadUint32()

		//i := int32(-836261582)
		blockHeader.Size = inputData.ReadUint32() ^ BlockHeaderSizeKey
		//i2 := int32(-1294620572)
		blockHeader.Addr = inputData.ReadUint32() ^ BlockHeaderAddrKey
		blockHeader.SizeAligned = blockHeader.Size
		//i3 := int32(-8)
		if (blockHeader.SizeAligned % 8) != 0 {
			blockHeader.SizeAligned = (blockHeader.SizeAligned & uint32(0xFFFFFFF8)) + 8
		}

		encryptedBlock := encryption.NewEncryptedBlock(int(blockHeader.SizeAligned))
		if n := inputData.Read(encryptedBlock); n != len(encryptedBlock) {
			panic(io.ErrUnexpectedEOF)
		}

		result = append(result, Block{
			Header: blockHeader,
			Block:  encryptedBlock,
		})
	}

	return result
}

func (fw Firmware) Length() int {
	if fw.FileHeader.IsAlmaCode() {
		panic("not implemented")
	}
	return len(fw.Data) - int(fw.FileHeader.HeaderSize)
}

func LoadFirmware(buf []byte) (f *Firmware, err error) {
	defer func() {
		if e := recover(); e != nil {
			var ok bool
			if err, ok = e.(error); !ok {
				err = fmt.Errorf("%s", e)
			}
		}
	}()

	fw := &Firmware{
		Data: buf,
	}
	dataBuf := buffer.Buffer(buf)
	_, err = dataBuf.Read(fw.FileHeader.Marker[:])
	if err != nil {
		return nil, err
	}

	isAlmaCode := bytes.Compare(fw.FileHeader.Marker[:], []byte(MarkerAlmaCode)) == 0

	if !isAlmaCode && bytes.Compare(fw.FileHeader.Marker[:], []byte(MarkerPhyton)) != 0 {
		return nil, errors.New("unsupported header")
	}

	fw.FileHeader.HeaderSize, err = dataBuf.ReadUint32()
	if err != nil {
		return nil, err
	}
	dataBuf = buf[len(fw.FileHeader.Marker)+4 : fw.FileHeader.HeaderSize]

	var dateTime uint32
	dateTime, err = dataBuf.ReadUint32()
	if err != nil {
		return nil, err
	}
	fw.FileHeader.DateTime = DateTime(dateTime)
	fw.FileHeader.BufferSize, err = dataBuf.ReadUint32()
	if err != nil {
		return nil, err
	}
	_, err = dataBuf.Read(fw.FileHeader.SerialNumber[:])
	if err != nil {
		return nil, err
	}

	if err = func() error {
		fw.FileHeader.VersionLow, err = dataBuf.ReadByte()
		if err != nil {
			return err
		}
		fw.FileHeader.VersionHigh, err = dataBuf.ReadByte()
		if err != nil {
			return err
		}
		fw.FileHeader.FileCount, err = dataBuf.ReadUint32()
		if err != nil {
			return err
		}
		fw.FileHeader.FirmwareHeaderSize, err = dataBuf.ReadUint32()
		if err != nil {
			return err
		}
		fw.FileHeader.Compressed, err = dataBuf.ReadByte()
		if err != nil {
			return err
		}
		fw.FileHeader.Reserved, err = dataBuf.ReadByte()
		if err != nil {
			return err
		}
		fw.FileHeader.CRC32, err = dataBuf.ReadUint32()
		if err != nil {
			return err
		}
		return nil
	}(); err != nil {
		if err != io.EOF {
			return nil, err
		}
	}

	if fw.FileHeader.IsAlmaCode() {
		for fileN := uint32(0); fileN < fw.FileHeader.FileCount; fileN++ {
			offset := fw.FileHeader.HeaderSize + fw.FileHeader.FirmwareHeaderSize*fileN
			fileBuffer := buffer.Buffer(buf[offset : offset+fw.FileHeader.FirmwareHeaderSize])
			var entry Entry
			_, err = fileBuffer.Read(entry.Header.Description[:])
			if err != nil {
				return nil, err
			}
			dateTime, err = fileBuffer.ReadUint32()
			if err != nil {
				return nil, err
			}
			entry.Header.DateTime = DateTime(dateTime)
			entry.Header.DataSize, err = fileBuffer.ReadUint32()
			entry.compressed = fw.FileHeader.Compressed > 0
			if err != nil {
				return nil, err
			}
			fw.Entries = append(fw.Entries, entry)
		}

		offset := fw.FileHeader.HeaderSize + fw.FileHeader.FirmwareHeaderSize*fw.FileHeader.FileCount
		for i, entry := range fw.Entries {
			fw.Entries[i].Blocks = BlocksFromData(fw.Data[offset : offset+entry.Header.DataSize])
			offset += entry.Header.DataSize
		}

		if offset != uint32(len(fw.Data)) {
			return nil, errors.New("data lingering after read")
		}
	} else {
		fw.Entries = append(fw.Entries, Entry{
			Header: ASFirmwareHeader{
				DateTime: fw.FileHeader.DateTime,
				DataSize: uint32(len(fw.Data[fw.FileHeader.HeaderSize:])),
			},
			Blocks:     BlocksFromData(fw.Data[fw.FileHeader.HeaderSize:]),
			compressed: fw.FileHeader.Compressed > 0,
		})
	}

	fw.FileHeader.UpdateCRC32 = crc.CalculateCRC(fw.Data)

	return fw, nil
}
