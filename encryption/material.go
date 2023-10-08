package encryption

type KeyMaterial struct {
	// Generator Random source to generate the inline material
	Generator         KeyGenerator
	OuterKeyOffset    OuterMangleKeyOffset
	DeviceKey         *MangleKeyData
	AlternateKeyTable *MangleKeyTable
}

func NewFlashKeyMaterial(generator KeyGenerator) KeyMaterial {
	return KeyMaterial{
		Generator:         generator,
		OuterKeyOffset:    OuterMangleKeyOffsetFlash,
		DeviceKey:         nil,
		AlternateKeyTable: nil,
	}
}

func NewMemoryKeyMaterial(generator KeyGenerator) KeyMaterial {
	return KeyMaterial{
		Generator:         generator,
		OuterKeyOffset:    OuterMangleKeyOffsetMemory,
		DeviceKey:         nil,
		AlternateKeyTable: nil,
	}
}

type OuterMangleKeyOffset int

const (
	OuterMangleKeyOffsetDefault  = 0
	OuterMangleKeyOffsetFlash    = OuterMangleKeyOffsetDefault
	OuterMangleKeyOffsetDeviceId = 1
	OuterMangleKeyOffsetMemory   = 6
)
