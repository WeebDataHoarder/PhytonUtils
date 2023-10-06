package compression

const DataMaxSize = 0x8000

const LiteralBits = 8

// OffsetBits Number of bits for the Window offset. From this the WindowSize will be calculated
// In other LZSS implementations, this is usually set to 12
const OffsetBits = 11
const LengthBits = 4

const WindowSize = 1 << OffsetBits

const MaxUncoded = 2
const MaxCoded = MaxUncoded + (1 << LengthBits)

// WindowInitialIndex The windowIndex needs to be set to this before compression/decompression
// In other LZSS implementations, this is usually set to 0
const WindowInitialIndex = WindowSize - 0x10 - 1

// WindowFillValue Initial value to fill Window[0 : WindowInitialIndex]
// In other LZSS implementations, this is usually set to 0x20, but Window[] is filled entirely
const WindowFillValue = 0x20
