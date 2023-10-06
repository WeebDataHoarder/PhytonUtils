package encryption

import (
	"encoding/binary"
	"math"
	"runtime"
	"slices"
	"sync"
)

func BruteforceBorlandSeed(b EncryptedBlock, material KeyMaterial) ([]uint32, error) {
	data := slices.Clone(b)
	err := data.Decrypt(material, false)
	if err != nil {
		return nil, err
	}

	numCpu := runtime.NumCPU()

	perCpu := math.MaxUint32 / numCpu

	firstValue := binary.LittleEndian.Uint16(data[2:])

	secondValue := binary.LittleEndian.Uint16(data[4:])

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
				currentSeed := BorlandRand(seed)
				seedA := uint16((currentSeed << 1) >> 0x11)
				currentSeed = BorlandRand(currentSeed)
				seedB := uint16((currentSeed << 1) >> 0x11)

				if seedA == firstValue && seedB == secondValue {
					if func() bool {
						for i := 4; i < 16; i += 2 {
							currentSeed = BorlandRand(currentSeed)
							if binary.LittleEndian.Uint16(data[2+i:]) != uint16((currentSeed<<1)>>0x11) {
								return false
							}
						}

						for i := 0; i < 0xf3; i++ {
							currentSeed = BorlandRand(currentSeed)

							if binary.LittleEndian.Uint16(data[0x1a+i*2:]) != uint16((currentSeed<<1)>>0x11) {
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
