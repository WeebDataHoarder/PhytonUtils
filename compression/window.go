package compression

type Window [WindowSize]byte

func CreateWindow() (t Window) {
	_ = t[WindowInitialIndex-1]

	// prefill lookup table
	for i := 0; i < WindowInitialIndex; i++ {
		t[i] = WindowFillValue
	}

	return t
}

func (t *Window) Find(windowIndex int, buf []byte, exhaustive bool) (offsetIndex, length int) {
	_ = buf[0]

	firstData := buf[0]

	offsetIndex = -1
	length = -1

	var t2 Window

	for i := range t {
		// Applying this offset compresses better in non-exhaustive mode
		currentOffsetIndex := t.Index(windowIndex + i - 1)
		if t[currentOffsetIndex] == firstData {
			t2 = *t

			var data byte
			lookupIndex2 := t2.SetByte(windowIndex, firstData)

			matchSize := 1

			for j := 1; j < len(buf) && j < (MaxCoded-1); j++ {
				if lookupIndex2, data = t2.GetSetByte(currentOffsetIndex+j, lookupIndex2); data != buf[j] {
					break
				}
				matchSize++
			}

			if matchSize > length && matchSize >= MaxUncoded {
				offsetIndex = currentOffsetIndex
				length = matchSize

				if !exhaustive {
					return
				}
			}
		}
	}

	return
}

func (t *Window) Peek(offsetIndex, length int, buf []byte) []byte {
	_ = buf[length-1]

	for j := 0; j < length; j++ {
		buf[j] = t[t.Index(offsetIndex+j)]
	}

	return buf[:length]
}

func (t *Window) GetSet(offsetIndex, windowIndex, length int, buf []byte) (int, []byte) {
	_ = buf[length-1]

	for j := 0; j < length; j++ {
		buf[j] = t[t.Index(offsetIndex+j)]
		t[t.Index(windowIndex+j)] = buf[j]
	}

	return t.Index(windowIndex + length), buf[:length]
}

func (t *Window) Set(windowIndex int, buf []byte) int {
	for j := range buf {
		t[t.Index(windowIndex+j)] = buf[j]
	}
	return t.Index(windowIndex + len(buf))
}

func (t *Window) GetSetByte(offsetIndex, windowIndex int) (int, byte) {
	data := t[t.Index(offsetIndex)]
	t[t.Index(windowIndex)] = data
	return t.Index(windowIndex + 1), data
}

func (t *Window) GetByte(offsetIndex int) byte {
	return t[t.Index(offsetIndex)]
}

func (t *Window) SetByte(windowIndex int, data byte) int {
	t[t.Index(windowIndex)] = data
	return t.Index(windowIndex + 1)
}

func (t *Window) Index(i int) int {
	return i & (WindowSize - 1)
}
