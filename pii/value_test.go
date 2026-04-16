package pii

import "testing"

func TestEncryptedValue_String(t *testing.T) {
	v := EncryptedValue("abc123")
	if got := v.String(); got != "abc123" {
		t.Errorf("String() = %q, want %q", got, "abc123")
	}
}

func TestEncryptedValue_IsEmpty(t *testing.T) {
	if !EncryptedValue("").IsEmpty() {
		t.Error("IsEmpty() = false for empty value, want true")
	}
	if EncryptedValue("abc").IsEmpty() {
		t.Error("IsEmpty() = true for non-empty value, want false")
	}
}

func TestRedacted(t *testing.T) {
	if Redacted.String() != "[REDACTED]" {
		t.Errorf("Redacted = %q, want %q", Redacted, "[REDACTED]")
	}
}
