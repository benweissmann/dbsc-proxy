package dbsctime

import (
	"time"
)

var mockNow *time.Time

func Now() time.Time {
	if mockNow != nil {
		return *mockNow
	}

	return time.Now()
}

func Since(t time.Time) time.Duration {
	return Now().Sub(t)
}

func Mock(t time.Time) {
	mockNow = &t
}

func MockAdvance(d time.Duration) {
	if mockNow == nil {
		panic("Cannot advance unmocked time")
	}

	Mock(Now().Add(d))
}

func MockReset() {
	mockNow = nil
}
