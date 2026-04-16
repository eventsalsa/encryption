package encryption

import "testing"

func TestZeroBytes(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("ZeroBytes: byte at index %d is %d, want 0", i, v)
		}
	}
}

func TestZeroBytesEmpty(t *testing.T) {
	b := []byte{}
	ZeroBytes(b) // should not panic
}

func TestZeroBytesNil(t *testing.T) {
	ZeroBytes(nil) // should not panic
}
