package secret

import "testing"

func TestNew(t *testing.T) {
	v := New("encrypted-data", 3)

	if v.Content != "encrypted-data" {
		t.Errorf("expected Content %q, got %q", "encrypted-data", v.Content)
	}
	if v.KeyVersion != 3 {
		t.Errorf("expected KeyVersion %d, got %d", 3, v.KeyVersion)
	}
}

func TestIsEmpty_True(t *testing.T) {
	v := New("", 1)

	if !v.IsEmpty() {
		t.Error("expected IsEmpty to be true for empty content")
	}
}

func TestIsEmpty_False(t *testing.T) {
	v := New("some-content", 1)

	if v.IsEmpty() {
		t.Error("expected IsEmpty to be false for non-empty content")
	}
}

func TestKeyVersionPreserved(t *testing.T) {
	versions := []int{0, 1, 42, 100}

	for _, ver := range versions {
		v := New("data", ver)
		if v.KeyVersion != ver {
			t.Errorf("expected KeyVersion %d, got %d", ver, v.KeyVersion)
		}
	}
}
