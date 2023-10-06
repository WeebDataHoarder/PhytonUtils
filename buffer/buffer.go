package buffer

import (
	"encoding/binary"
	"io"
	"math"
)

type Buffer []byte

func (b *Buffer) ReadByte() (uint8, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	defer func() {
		*b = (*b)[1:]
	}()
	return (*b)[0], nil
}

func (b *Buffer) Read(buf []byte) (int, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	if len(*b) < len(buf) {
		defer func() {
			*b = nil
		}()
		copy(buf, *b)
		return len(*b), io.ErrUnexpectedEOF
	}

	defer func() {
		*b = (*b)[len(buf):]
	}()
	copy(buf, *b)
	return len(buf), nil
}

func (b *Buffer) Skip(n int) error {
	if len(*b) == 0 {
		return io.EOF
	}
	if len(*b) < n {
		return io.ErrUnexpectedEOF
	}
	*b = (*b)[n:]
	return nil
}

func (b *Buffer) ReadInt32() (int32, error) {
	var buf [4]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(buf[:])), nil
}

func (b *Buffer) ReadUint32() (uint32, error) {
	var buf [4]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func (b *Buffer) ReadUint32BE() (uint32, error) {
	var buf [4]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

func (b *Buffer) ReadFloat32() (float32, error) {
	var buf [4]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(buf[:])), nil
}

func (b *Buffer) ReadInt16() (int16, error) {
	var buf [2]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return int16(binary.LittleEndian.Uint16(buf[:])), nil
}

func (b *Buffer) ReadUint16() (uint16, error) {
	var buf [2]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(buf[:]), nil
}

func (b *Buffer) ReadUint16BE() (uint16, error) {
	var buf [2]byte
	_, err := io.ReadFull(b, buf[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

func (b *Buffer) ReadBytes() ([]byte, error) {
	l, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(b, buf[:])
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *Buffer) ReadString() (string, error) {
	buf, err := b.ReadBytes()
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

type PanicBuffer []byte

func (b *PanicBuffer) ReadByte() uint8 {
	v, err := (*Buffer)(b).ReadByte()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) Read(buf []byte) int {
	v, err := (*Buffer)(b).Read(buf)
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) Skip(n int) {
	err := (*Buffer)(b).Skip(n)
	if err != nil {
		panic(err)
	}
}

func (b *PanicBuffer) ReadInt32() int32 {
	v, err := (*Buffer)(b).ReadInt32()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadUint32() uint32 {
	v, err := (*Buffer)(b).ReadUint32()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadUint32BE() uint32 {
	v, err := (*Buffer)(b).ReadUint32BE()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadFloat32() float32 {
	v, err := (*Buffer)(b).ReadFloat32()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadInt16() int16 {
	v, err := (*Buffer)(b).ReadInt16()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadUint16() uint16 {
	v, err := (*Buffer)(b).ReadUint16()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadUint16BE() uint16 {
	v, err := (*Buffer)(b).ReadUint16BE()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadBytes() []byte {
	v, err := (*Buffer)(b).ReadBytes()
	if err != nil {
		panic(err)
	}
	return v
}

func (b *PanicBuffer) ReadString() string {
	v, err := (*Buffer)(b).ReadString()
	if err != nil {
		panic(err)
	}
	return v
}
