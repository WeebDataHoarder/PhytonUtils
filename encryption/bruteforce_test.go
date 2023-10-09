package encryption

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"slices"
	"testing"
)

func TestBruteforceSeed_Short(t *testing.T) {
	data := slices.Clone(sampleBlockMemoryEmpty)

	seeds, err := BruteforceBorlandSeed(data, NewMemoryKeyMaterial(nil))
	if err != nil {
		t.Fatal(err)
	}

	seed := uint32(0)

	t.Logf("original seed = 0x%08x", seed)

	for _, seed := range seeds {
		t.Logf("possible seed = 0x%08x", seed)
	}

	if !slices.Contains(seeds, seed) {
		t.Fatal("seed not found")
	}
}

func TestBruteforceSeed_Random(t *testing.T) {

	t.Parallel()

	var err error

	b := NewEncryptedBlock(0)

	var seedBuf [4]byte
	_, err = io.ReadFull(rand.Reader, seedBuf[:])
	seed := binary.LittleEndian.Uint32(seedBuf[:])
	generator := BorlandRandKeyGenerator(seed)
	material := NewMemoryKeyMaterial(&generator)
	err = b.Encrypt(material)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("original seed = 0x%08x", seed)

	data := slices.Clone(b)

	seeds, err := BruteforceBorlandSeed(data, material)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("original seed = 0x%08x", seed)

	for _, seed := range seeds {
		t.Logf("possible seed = 0x%08x", seed)
	}

	if !slices.Contains(seeds, seed) {
		t.Fatal("seed not found")
	}
}

func TestBruteforceSeed_Byte_Random(t *testing.T) {
	t.Parallel()

	var err error

	b := NewEncryptedBlock(0)

	var seedBuf [4]byte
	_, err = io.ReadFull(rand.Reader, seedBuf[:])
	seed := binary.LittleEndian.Uint32(seedBuf[:])
	generator := BorlandRandByteKeyGenerator(seed)
	material := NewMemoryKeyMaterial(&generator)
	err = b.Encrypt(material)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("original seed = 0x%08x", seed)

	data := slices.Clone(b)

	seeds, err := BruteforceBorlandSeedBytes(data, material)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("original seed = 0x%08x", seed)

	for _, seed := range seeds {
		t.Logf("possible seed = 0x%08x", seed)
	}

	if !slices.Contains(seeds, seed) {
		t.Fatal("seed not found")
	}
}

func TestBruteforceSeed_FirmwareUncompressed(t *testing.T) {
	data := slices.Clone(sampleBlockFirmwareUncompressed)

	_, err := BruteforceBorlandSeed(data, NewFlashKeyMaterial(nil))
	if err == nil || err.Error() != "not a borland rand seed" {
		t.Fatal("error expected: \"not a borland rand seed\"")
	}
}

func TestBruteforceSeed_FirmwareCompressed(t *testing.T) {
	data := slices.Clone(sampleBlockFirmwareCompressed)

	_, err := BruteforceBorlandSeed(data, NewFlashKeyMaterial(nil))
	if err == nil || err.Error() != "not a borland rand seed" {
		t.Fatal("error expected: \"not a borland rand seed\"")
	}
}
