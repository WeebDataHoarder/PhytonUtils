package encryption

import (
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"slices"
	"sync"
)

// IsKeyBorlandSeedLikely The generator used on BorlandRand does not set the highest bit, as such it can be detected
func IsKeyBorlandSeedLikely(b EncryptedBlock, material KeyMaterial) bool {
	data := slices.Clone(b)
	err := data.Decrypt(material, false)
	if err != nil {
		return false
	}

	for i := EncryptedBlockMangleKeyOffset; i < EncryptedBlockCRC1Offset; i += 2 {
		if binary.LittleEndian.Uint16(data[i:])&0x8000 > 0 {
			return false
		}
	}

	for i := EncryptedBlockPaddingKeyOffset; i < EncryptedBlockKeySize; i += 2 {
		if binary.LittleEndian.Uint16(data[i:])&0x8000 > 0 {
			return false
		}
	}

	return true
}

func BruteforceBorlandSeed(b EncryptedBlock, material KeyMaterial) ([]uint32, error) {
	//TODO: this can be done more efficiently as LCG leaks 16 bits each time, by backwards looping and solving across uint16 range

	if !IsKeyBorlandSeedLikely(b, material) {
		return nil, errors.New("not a borland rand seed")
	}

	data := slices.Clone(b)
	err := data.Decrypt(material, false)
	if err != nil {
		return nil, err
	}

	numCpu := runtime.NumCPU()

	perCpu := math.MaxUint32 / numCpu

	firstValue := binary.LittleEndian.Uint16(data[EncryptedBlockMangleKeyOffset:])

	secondValue := binary.LittleEndian.Uint16(data[EncryptedBlockMangleKeyOffset+2:])

	var foundSeeds []uint32
	var foundSeedsLock sync.Mutex

	var wg sync.WaitGroup
	for cpu := 0; cpu < numCpu; cpu++ {
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			seed := uint32(cpu * perCpu)
			endSeed := seed + uint32(perCpu)
			if cpu == (numCpu - 1) {
				endSeed = math.MaxUint32
			}

			for {
				currentSeed, output := BorlandRand(seed)
				seedA := output
				currentSeed, output = BorlandRand(currentSeed)
				seedB := output

				if seedA == firstValue && seedB == secondValue {
					if func() bool {
						for i := EncryptedBlockMangleKeyOffset + 4; i < EncryptedBlockCRC1Offset; i += 2 {
							currentSeed, output = BorlandRand(currentSeed)
							if binary.LittleEndian.Uint16(data[i:]) != output {
								return false
							}
						}

						for i := EncryptedBlockPaddingKeyOffset; i < EncryptedBlockKeySize; i += 2 {
							currentSeed, output = BorlandRand(currentSeed)

							if binary.LittleEndian.Uint16(data[i:]) != output {
								return false
							}
						}

						return true
					}() {
						func() {
							foundSeedsLock.Lock()
							defer foundSeedsLock.Unlock()
							foundSeeds = append(foundSeeds, seed)
						}()
					}
				}

				if seed == endSeed {
					break
				}
				seed++
			}

			return

		}(cpu)
	}

	wg.Wait()

	slices.Sort(foundSeeds)

	return foundSeeds, nil
}
