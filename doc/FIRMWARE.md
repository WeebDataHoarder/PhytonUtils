# Firmware notes

## ASFileHeader
|         Field          |    Type    |            Size            |                                                                Notes                                                                 |
|:----------------------:|:----------:|:--------------------------:|:------------------------------------------------------------------------------------------------------------------------------------:|
|        *Marker*        | `[8]byte`  |             8              |                                            Can be either `Phyton\x00\x00` or `AlmaCode`.                                             |
|     *Header Size*      |  `uint32`  |             4              |                             Size of whole Header struct. Fields may be omitted if they exceed the size.                              |
|      *Date Time*       |  `uint32`  |             4              |                                             Release time in _FirmwareDateTime_ encoding.                                             |
|     *Buffer Size*      |  `uint32`  |             4              |                                                                 TBD                                                                  |
|    *Serial Number*     | `[16]byte` |             16             |                                     Firmware coded for a specific device S/N. Usually all zeros.                                     |
|     *Version Low*      |  `uint8`   |             1              |                                                                                                                                      |
|     *Version High*     |  `uint8`   |             1              |                                                                                                                                      |
|       *Version*        |     -      |             -              |                 Derived from _Version Low_ and _Version High_.<br/>`fmt.Sprintf("%d.%02d", VersionHigh, VersionLow)`                 |
|      *File Count*      |  `uint32`  |             4              |                                               TBD. Only used if _Marker_ == `AlmaCode`                                               |
| *Firmware Header Size* |  `uint32`  |             4              |                                                                 TBD                                                                  |
|      *Compressed*      |   `bool`   |             1              |                                          Set to `1` on files with compressed FirmwareBlock.                                          |
|       *Reserved*       |  `uint8`   |             1              |                                                             Set to `0`.                                                              |
|        *CRC32*         |  `uint32`  |             4              |                                                Contains the [CRC](CRC.md) of _Data_.                                                 |
|         *Data*         |  `[]byte`  | _len(buf)_ - _Buffer Size_ | In case of  _Marker_ == `Phyton\x00\x00`, `[]FirmwareBlock` follows until EOF.<br/>Refer to source code to decode `AlmaCode` format. | 

#### DateTime
```go
package radiacode

import "time"

func DateTimeToTime(dt uint32) time.Time {
	high := uint16(dt >> 16)
	low := uint16(dt)

	year := ((high >> 9) & 127) + 1980
	month := (high >> 5) & 15
	day := high & 31
	hours := (low >> 11) & 31
	minutes := (low >> 5) & 63
	seconds := (low & 31) * 2

	return time.Date(int(year), time.Month(month), int(day), int(hours), int(minutes), int(seconds), 0, time.UTC)
}
```


## Block
|     Field      |    Type     |   XOR Key    |      Size      |                                                          Notes                                                           |
|:--------------:|:-----------:|:------------:|:--------------:|:------------------------------------------------------------------------------------------------------------------------:|
| *Header Size*  |  `uint32`   |      -       |       4        | Denotes the size of the header.<br/>Should be 12, but some weird cases exist in firmware to pad it, 0 value, or 0xFFFF?. |
|     *Size*     |  `uint32`   | _0xCE27A932_ |       4        |                                                                                                                          |
|     *Addr*     |  `uint32`   | _0xB2D5A864_ |       4        |                                         Denotes the location of _Data_ in Flash.                                         |
| *Size Aligned* |      -      |      -       |       -        |              Derived from _Size_, 8 byte alignment. See [Size Aligned derivation](#size-aligned-derivation)              |
|   *Key Data*   | `[512]byte` |      -       |      512       |                                                     Encryption keys                                                      |
|     *Data*     |  `[]byte`   |      -       | _Size Aligned_ |                                                                                                                          | 

After each _FirmwareBlock_ a new one follows, or EOF. So far each new one addresses the next memory block sequentially, without gaps.

Note that if _ASFileHeader_ has _Compressed_ field set, the Data will be smaller than the actual region.

#### Size Aligned derivation

```go
package radiacode

func AlignSize(size uint32) uint32 {
	if (size % 8) != 0 {
		size = (size & uint32(0xFFFFFFF8)) + 8
	}
	return size
}
```

## Encryption of Block Key + Data
See [Encryption notes](ENCRYPTION.md)

## Compression of FirmwareBlock Data
See [Compression notes](COMPRESSION.md)