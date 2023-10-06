package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/compression"
	"git.gammaspectra.live/WeebDataHoarder/PhytonUtils/crc"
	"io"
	"slices"
	"testing"
)

func TestEncryptedBlock_Decrypt_FirmwareUncompressed(t *testing.T) {
	t.Parallel()

	data := slices.Clone(sampleBlockFirmwareUncompressed)
	err := data.Decrypt(NewFirmwareKeyMaterial(nil), true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedBlock_Decrypt_FirmwareCompressed(t *testing.T) {
	t.Parallel()

	data := slices.Clone(sampleBlockFirmwareCompressed)
	err := data.Decrypt(NewFirmwareKeyMaterial(nil), false)
	if err != nil {
		t.Fatal(err)
	}

	rawCompressedData := data.DataBlock()[:sampleBlockFirmwareCompressedSize]

	decompressedData, err := compression.FirmwareBlockDecompress(rawCompressedData)
	if err != nil {
		t.Fatal(err)
	}

	crc1, _ := data.CRC()

	if calculatedCrc := crc.CalculateCRC(decompressedData); calculatedCrc != crc1 {
		t.Fatalf("decompressed data does not match, %08x != %08x", calculatedCrc, crc1)
	}

	compressedDataExhaustive, err := compression.FirmwareBlockCompress(decompressedData, true)
	if err != nil {
		t.Fatal(err)
	}

	decompressedData2, err := compression.FirmwareBlockDecompress(compressedDataExhaustive)
	if err != nil {
		t.Fatal(err)
	}

	if calculatedCrc := crc.CalculateCRC(decompressedData2); calculatedCrc != crc1 {
		t.Fatalf("compressed and decompressed exhaustive data does not match, %08x != %08x", calculatedCrc, crc1)
	}

	compressedData, err := compression.FirmwareBlockCompress(decompressedData, false)
	if err != nil {
		t.Fatal(err)
	}

	decompressedData3, err := compression.FirmwareBlockDecompress(compressedData)
	if err != nil {
		t.Fatal(err)
	}

	if calculatedCrc := crc.CalculateCRC(decompressedData3); calculatedCrc != crc1 {
		t.Fatalf("compressed and decompressed data does not match, %08x != %08x", calculatedCrc, crc1)
	}

	t.Logf("Decompressed size: %d", len(decompressedData))
	t.Logf("Original compressed size: %d", len(rawCompressedData))
	t.Logf("Custom compressed size: %d", len(compressedData))
	t.Logf("Custom compressed size (exhaustive): %d", len(compressedDataExhaustive))

	originalRatio := float64(len(rawCompressedData)) / float64(len(decompressedData))
	customRatio := float64(len(compressedData)) / float64(len(decompressedData))
	customRatioExhaustive := float64(len(compressedDataExhaustive)) / float64(len(decompressedData))
	t.Logf("Original ratio: %.08f%%", originalRatio*100)
	t.Logf("Custom ratio: %.08f%%", customRatio*100)
	t.Logf("Custom ratio (exhaustive): %.08f%%", customRatioExhaustive*100)
	t.Logf("Change: %.08f%%", (customRatio-originalRatio)*100)
	t.Logf("Change (exhaustive): %.08f%%", (customRatioExhaustive-originalRatio)*100)
}

func TestEncryptedBlock_Decrypt_MemoryData(t *testing.T) {
	t.Parallel()

	data := slices.Clone(sampleBlockMemoryEmpty)
	err := data.Decrypt(NewMemoryKeyMaterial(nil), true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedBlock_EncryptDecrypt(t *testing.T) {
	t.Parallel()

	b := NewEncryptedBlock(64)
	_, err := io.ReadFull(rand.Reader, b.DataBlock())
	if err != nil {
		t.Fatal(err)
	}
	data := slices.Clone(b.DataBlock())

	var seedBuf [4]byte
	_, err = io.ReadFull(rand.Reader, seedBuf[:])
	material := NewMemoryKeyMaterial(&SecureRandomKeyGenerator{})
	b.Encrypt(material)

	dec := slices.Clone(b)
	err = dec.Decrypt(material, true)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, dec.DataBlock()) != 0 {
		t.Fatal("data does not match")
	}
}

func TestEncryptedBlock_EncryptDecrypt_WithDeviceKey(t *testing.T) {
	t.Parallel()

	b := NewEncryptedBlock(64)
	_, err := io.ReadFull(rand.Reader, b.DataBlock())
	if err != nil {
		t.Fatal(err)
	}
	data := slices.Clone(b.DataBlock())

	var seedBuf [4]byte
	_, err = io.ReadFull(rand.Reader, seedBuf[:])
	generator := BorlandRandKeyGenerator(binary.LittleEndian.Uint32(seedBuf[:]))
	material := NewFirmwareKeyMaterial(&generator)
	material.DeviceKey = sampleDeviceMangleKey
	b.Encrypt(material)

	dec := slices.Clone(b)
	err = dec.Decrypt(material, true)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, dec.DataBlock()) != 0 {
		t.Fatal("data does not match")
	}
}

func TestEncryptedBlock_Encrypt(t *testing.T) {
	t.Parallel()

	var err error

	b := NewEncryptedBlock(0)
	generator := BorlandRandKeyGenerator(0)
	material := NewMemoryKeyMaterial(&generator)
	b.Encrypt(material)

	d1 := slices.Clone(b)
	d2 := slices.Clone(sampleBlockMemoryEmpty)

	err = d1.Decrypt(material, true)
	if err != nil {
		t.Fatal(err)
	}
	err = d2.Decrypt(material, true)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(d1, d2) != 0 {
		t.Logf("generated %x", d1)
		t.Logf("expected %x", d2)
		t.Fail()
	}

	if bytes.Compare(b, sampleBlockMemoryEmpty) != 0 {
		t.Logf("generated %x", b)
		t.Logf("expected %x", sampleBlockMemoryEmpty)
		t.Fail()
	}
}

func TestBruteforceSeed_Short(t *testing.T) {
	data := slices.Clone(sampleBlockMemoryEmpty)

	seeds, err := BruteforceBorlandSeed(data, NewMemoryKeyMaterial(nil))
	if err != nil {
		t.Fatal(err)
	}

	for _, seed := range seeds {
		t.Logf("seed = 0x%08x", seed)
	}

	if len(seeds) != 2 {
		t.Fatal("seeds not found")
	}
}

/*
func TestBruteforceSeed_FirmwareUncompressed(t *testing.T) {
	data := slices.Clone(sampleBlockFirmwareUncompressed)

	seeds, err := BruteforceBorlandSeed(data, NewFirmwareKeyMaterial(nil))
	if err != nil {
		t.Fatal(err)
	}

	for _, seed := range seeds {
		t.Logf("found seed = 0x%08x", seed)
	}

	if len(seeds) != 2 {
		t.Fatal("seeds not found")
	}
}
*/

func BenchmarkEncryptedBlock_Encrypt(b *testing.B) {
	const dataSize = 64
	const keyOffset = OuterMangleKeyOffsetMemory
	data := make([]byte, dataSize)

	_, err := io.ReadFull(rand.Reader, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {

		buf := NewEncryptedBlock(len(data))
		var material KeyMaterial
		material.OuterKeyOffset = keyOffset
		generator := BorlandRandKeyGenerator(0)
		material.Generator = &generator

		for pb.Next() {
			buf.Reset()
			copy(buf.DataBlock(), data)
			buf.Encrypt(material)
		}
	})
}

func BenchmarkEncryptedBlock_Decrypt(b *testing.B) {
	const dataSize = 64
	const keyOffset = OuterMangleKeyOffsetMemory

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		encryptedBlock := NewEncryptedBlock(dataSize)
		_, err := io.ReadFull(rand.Reader, encryptedBlock.DataBlock())
		if err != nil {
			b.Fatal(err)
		}

		var seedBuf [4]byte
		_, err = io.ReadFull(rand.Reader, seedBuf[:])

		var material KeyMaterial
		material.OuterKeyOffset = keyOffset
		generator := BorlandRandKeyGenerator(binary.LittleEndian.Uint32(seedBuf[:]))
		material.Generator = &generator

		encryptedBlock.Encrypt(material)

		buf := NewEncryptedBlock(len(encryptedBlock.DataBlock()))
		for pb.Next() {
			buf.Reset()
			copy(buf, encryptedBlock)
			err = buf.Decrypt(material, true)
			if err != nil {
				panic(err)
			}
		}
	})
}
