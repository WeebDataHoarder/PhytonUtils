package encryption

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"slices"
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

	if !IsKeyBorlandSeedLikely(b, material) {
		return nil, errors.New("not a borland rand seed")
	}

	data := slices.Clone(b)
	err := data.Decrypt(material, false)
	if err != nil {
		return nil, err
	}
	// Efficient search as LCG leaks 15 bits each time, by backwards looping and solving across uint17 range

	const dataSize = 2
	const stateDataStart = EncryptedBlockMangleKeyOffset
	const stateDataEnd = EncryptedBlockCRC1Offset - dataSize
	validStateBits := bits.OnesCount32(BorlandRandOutputMask)
	validStateInverseBits := bits.OnesCount32(^BorlandRandOutputMask)
	var stateOutputMask = BorlandRandOutputMask << BorlandRandOutputShift

	statesBuf := make([]uint32, 0, 32-validStateBits)
	getPossibleStates := func(state uint32, previousOutput uint16) (states []uint32) {
		var seed, prevSeed uint32

		states = statesBuf[:0]

		var limit uint32 = 1 << validStateInverseBits
		for n := uint32(0); n < limit; n++ {
			// Fills the output part of the state
			seed = (state & stateOutputMask) | ((n & (^uint32(0xFFFF))) << validStateBits) | (n & 0xFFFF)

			prevSeed = BorlandRandPreviousSeed(seed)

			if BorlandRandOutput(prevSeed) == previousOutput {
				states = append(states, prevSeed)
			}
		}
		return states
	}

	var possibleStates []uint32

	stateIndex := stateDataEnd
	{
		previousOutput := binary.LittleEndian.Uint16(data.KeyBlock()[stateIndex-dataSize:])
		var nextStates []uint32
		previousState := (uint32(binary.LittleEndian.Uint16(data.KeyBlock()[stateIndex:])) << BorlandRandOutputShift) & stateOutputMask
		states := getPossibleStates(previousState, previousOutput)
		if len(nextStates) == 0 {
			nextStates = states
			states = slices.Compact(states)
			nextStates = slices.Clone(states)
		} else {
			for i := len(nextStates) - 1; i >= 0; i-- {
				if !slices.Contains(states, nextStates[i]) {
					nextStates = slices.Delete(nextStates, i, i+1)
				}
			}
		}

		slices.Sort(nextStates)
		nextStates = slices.Compact(nextStates)
		possibleStates = nextStates

		stateIndex -= dataSize
	}

	//Last rounds backwards with checks
	for ; stateIndex >= stateDataStart; stateIndex -= dataSize {
		for j := len(possibleStates) - 1; j >= 0; j-- {
			prevState := BorlandRandPreviousSeed(possibleStates[j])
			if _, output := BorlandRand(prevState); output != binary.LittleEndian.Uint16(data.KeyBlock()[stateIndex:]) {
				possibleStates = slices.Delete(possibleStates, j, j+1)
				continue
			}
			possibleStates[j] = prevState
		}
	}

	slices.Sort(possibleStates)
	possibleStates = slices.Compact(possibleStates)

	return possibleStates, err
}

func BruteforceBorlandSeedBytes(b EncryptedBlock, material KeyMaterial) ([]uint32, error) {

	data := slices.Clone(b)
	err := data.Decrypt(material, false)
	if err != nil {
		return nil, err
	}
	// Efficient search as LCG leaks 8 bits each time, by backwards looping and solving across uint24 range

	const dataSize = 1
	const stateDataStart = EncryptedBlockMangleKeyOffset
	const stateDataEnd = EncryptedBlockCRC1Offset - dataSize
	const byteOutputMask = BorlandRandOutputMask & 0xFF
	validStateBits := bits.OnesCount32(byteOutputMask)
	validStateInverseBits := bits.OnesCount32(^byteOutputMask)
	var stateOutputMask = byteOutputMask << BorlandRandOutputShift

	statesBuf := make([]uint32, 0, 32-validStateBits)
	getPossibleStates := func(state uint32, previousOutput uint8) (states []uint32) {
		var seed, prevSeed uint32

		states = statesBuf[:0]

		var limit uint32 = 1 << validStateInverseBits
		for n := uint32(0); n < limit; n++ {
			// Fills the output part of the state
			seed = (state & stateOutputMask) | ((n & (^uint32(0xFFFF))) << validStateBits) | (n & 0xFFFF)

			prevSeed = BorlandRandPreviousSeed(seed)

			if uint8(BorlandRandOutput(prevSeed)) == previousOutput {
				states = append(states, prevSeed)
			}
		}
		return states
	}

	var possibleStates []uint32

	stateIndex := stateDataEnd

	{
		previousOutput := data.KeyBlock()[stateIndex-dataSize]
		var nextStates []uint32
		previousState := (uint32(data.KeyBlock()[stateIndex]) << BorlandRandOutputShift) & stateOutputMask
		states := getPossibleStates(previousState, previousOutput)
		if len(nextStates) == 0 {
			slices.Sort(states)
			states = slices.Compact(states)
			nextStates = slices.Clone(states)
		} else {
			for i := len(nextStates) - 1; i >= 0; i-- {
				if !slices.Contains(states, nextStates[i]) {
					nextStates = slices.Delete(nextStates, i, i+1)
				}
			}
		}

		slices.Sort(nextStates)
		nextStates = slices.Compact(nextStates)
		possibleStates = nextStates

		stateIndex -= dataSize
	}

	//Last rounds backwards with checks
	for ; stateIndex >= stateDataStart; stateIndex -= dataSize {
		for j := len(possibleStates) - 1; j >= 0; j-- {
			prevState := BorlandRandPreviousSeed(possibleStates[j])
			if _, output := BorlandRand(prevState); uint8(output) != data.KeyBlock()[stateIndex] {
				possibleStates = slices.Delete(possibleStates, j, j+1)
				continue
			}
			possibleStates[j] = prevState
		}
	}

	slices.Sort(possibleStates)
	possibleStates = slices.Compact(possibleStates)

	return possibleStates, err
}
