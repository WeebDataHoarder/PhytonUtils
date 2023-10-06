# Encryption notes

## Mangle Block Cipher
This cipher is used on encryption of firmware and memory data. The name Mangle has been arbitrarily chosen.

### Mangle Key
A mangle key is a 128-bit sequence of bytes, either fixed or dynamically generated.
Some of these keys are stored in Tables listed below.

Each Mangle Key is split in 4 `uint32` sub-keys. These are selected depending on the round number. 

Some of these keys are organized in key tables. This is a collection of 8 128-bit keys in an addressable way.

### Design
Mangle is an iterative, 64-bit block cipher.
Directly, 128-bit keys are used, but several of these are combined in the full Mangle construct.

The round function is composed of two parts, that mix the data of the two halves.

For each block, 48 rounds are applied consecutively, with each round modifying one of the halves alternatively.

```go
package mangle

type Key [4]uint32

const Rounds = 48

func Encrypt(key Key, block uint64) uint64 {
	dataA, dataB := uint32(block), uint32(block>>32)
	for round := int32(0); round < Rounds; round++ {
		// Swap dataA and dataB
		dataB, dataA = encryptRound(key[(round&3)<<2], dataA, dataB, uint32(round))
	}
	return uint64(dataA) | (uint64(dataB) << 32)
}

func encryptRound(roundKey uint32, dataA, dataB, round uint32) (uint32, uint32) {
	dataA = round + roundKey + ((dataB >> 8) ^ (dataB << 6)) + dataB + dataA
	return dataA, dataB
}

func Decrypt(key Key, block uint64) uint64 {
	dataA, dataB := uint32(block), uint32(block>>32)
	// Rounds run inverse to Encrypt
	for round := int32(Rounds - 1); round != -1; round-- {
		// Swap dataA and dataB
		dataA, dataB = decryptRound(key[(round&3)<<2], dataB, dataA, uint32(round))
	}
	return uint64(dataA) | (uint64(dataB) << 32)
}

func decryptRound(roundKey uint32, dataA, dataB, round uint32) (uint32, uint32) {
	dataA = (dataA - dataB) - ((dataB >> 8) ^ (dataB << 6)) - roundKey - round
	return dataA, dataB
}
```

### Mode of operation
The cipher operates in ECB mode. As such, blocks containing the same value will encrypt equally.

Attacking this cipher without knowledge of key material or algorithm is trivial,
given access to an Encryption Oracle and starting knowledge of a full 64-bit block in target material.


### Hardcoded Mangle Key Table

This table is hardcoded in firmware, and seems to be used across all devices known.

It gets used on the Outer Mangle and the Inner Mangle, depending on the selected Mangle Index.

| Offset | Identifier |                     Key Data                     |
|:------:|:----------:|:------------------------------------------------:|
|   0    | _Firmware_ | `0x0539c06f, 0x3a235801, 0x1bb4da80, 0x44916a65` |
|   1    | _DeviceId_ | `0x5b01cb35, 0xb498a4fb, 0xe9486d82, 0xf4945010` |
|   2    |            | `0xe8babcec, 0x2aa73df8, 0x4cf9f79c, 0x886d73e7` |
|   3    |            | `0x25483503, 0xb1a0a8af, 0x24a745b2, 0xf5e21339` |
|   4    |            | `0x42d89088, 0x37a379af, 0x422689e0, 0x636239e9` |
|   5    |            | `0xabd061f0, 0x7f710579, 0xbd626b51, 0x2af22c15` |
|   6    |  _Memory_  | `0xb341bc06, 0x6e6e4674, 0xb3eb7b01, 0xf1965b32` |
|   7    |            | `0x52f33e6f, 0x4d69a2f9, 0x77ab77c4, 0x468f4508` |

Several offsets from this table are used for either the outer mangle or other purposes.
* #0: _Firmware Outer Mangle Key_
* #1: _Device Id Outer Mangle Key_
* #6: _Memory Outer Mangle Key_

### Alternate Mangle Key Table

This table is hardcoded in firmware, however, seems to be set to all zeros. No usages in the wild have been found.

It gets used on the Inner Mangle, depending on the selected Mangle Index.

| Offset |                     Key Data                     |
|:------:|:------------------------------------------------:|
|   0    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   1    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   2    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   3    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   4    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   5    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   6    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |
|   7    | `0x00000000, 0x00000000, 0x00000000, 0x00000000` |


### Data Mangle Key
This key is randomly generated via various methods. It is 512 bytes long,
and includes the CRC of the original data being encrypted (before compression) twice.

Structure is as follows:
```
Mangle Index (2 bytes)
    blob[0:2] = Mangle Index uint16
Mangle Key Block (24 bytes)
    blob[2:18] = random() Data Mangle Key
    blob[18:22] = CRC(data)
    blob[22:26] = CRC(data)
Unused Key Block (486 bytes)    
    blob[26:512] = random() Unused
```

Although the blob generated is 512 bytes long, only `blob[2:18]` is used as the Key, which does not include the CRC.

### Device Id Specific Mangle Key
Data can be coded specifically to a given device id, which is local to the device.

It gets used on the Inner Mangle, depending on the selected Mangle Index.

Slot #1 from the _Hardcoded Mangle Key Table_ is used here.

```go
package mangle

type Key [4]uint32
var HardcodedKeyTable [8]Key

func DeviceKey(deviceId1, deviceId2, deviceId3 uint32) (key Key) {
	outerKey := HardcodedKeyTable[1]
	key[0] = outerKey[0] ^ deviceId1
	key[1] = outerKey[1] ^ deviceId2
	key[2] = outerKey[2] ^ deviceId3
	key[3] = outerKey[3]
	return key
}
```
