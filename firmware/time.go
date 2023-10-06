package firmware

import "time"

type DateTime uint32

func (dt DateTime) Time() time.Time {
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

func (dt DateTime) String() string {
	return dt.Time().String()
}
