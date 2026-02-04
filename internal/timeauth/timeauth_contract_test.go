package timeauth

import (
	"testing"
	"time"
)

func TestPlaceholderAuthority_Name(t *testing.T) {
	authority := &PlaceholderAuthority{}
	
	if authority.Name() != "placeholder" {
		t.Errorf("expected name 'placeholder', got %s", authority.Name())
	}
}

func TestPlaceholderAuthority_Lock(t *testing.T) {
	authority := &PlaceholderAuthority{}
	unlockTime := time.Now().UTC().Add(24 * time.Hour)

	ref, err := authority.Lock(unlockTime)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should return a deterministic key reference
	if ref == "" {
		t.Error("key reference should not be empty")
	}

	if string(ref) != "placeholder-key-ref" {
		t.Errorf("expected key reference 'placeholder-key-ref', got %s", ref)
	}
}

func TestPlaceholderAuthority_CanUnlock_AlwaysFalse(t *testing.T) {
	authority := &PlaceholderAuthority{}
	ref := KeyReference("placeholder-key-ref")

	testCases := []struct {
		name string
		now  time.Time
	}{
		{"past", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"present", time.Now().UTC()},
		{"future", time.Now().UTC().Add(100 * 365 * 24 * time.Hour)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			canUnlock, err := authority.CanUnlock(ref, tc.now)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if canUnlock {
				t.Error("placeholder authority should never permit unlocking")
			}
		})
	}
}
