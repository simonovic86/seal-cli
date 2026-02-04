package timeauth

import (
	"context"
	"testing"
	"time"
)

// TestAuthorityContract_Name verifies that all authorities return a non-empty name
func TestAuthorityContract_Name(t *testing.T) {
	authorities := []Authority{
		&PlaceholderAuthority{},
		&FakeAuthority{AuthorityName: "test-fake"},
	}

	for _, auth := range authorities {
		t.Run(auth.Name(), func(t *testing.T) {
			name := auth.Name()
			if name == "" {
				t.Error("Name() should not return empty string")
			}
		})
	}
}

// TestAuthorityContract_RoundAt verifies that all authorities can calculate rounds
func TestAuthorityContract_RoundAt(t *testing.T) {
	futureTime := time.Now().UTC().Add(24 * time.Hour)

	authorities := map[string]Authority{
		"placeholder": &PlaceholderAuthority{},
		"fake":        &FakeAuthority{DefaultRound: 1000},
	}

	for name, auth := range authorities {
		t.Run(name, func(t *testing.T) {
			_, err := auth.RoundAt(futureTime)
			// Should not error for valid future time
			if err != nil {
				t.Errorf("RoundAt should not error for valid future time: %v", err)
			}
		})
	}
}

// TestAuthorityContract_CanUnlock verifies that all authorities can check unlock status
func TestAuthorityContract_CanUnlock(t *testing.T) {
	ctx := context.Background()

	authorities := map[string]Authority{
		"placeholder": &PlaceholderAuthority{},
		"fake":        &FakeAuthority{CurrentRound: 1000},
	}

	for name, auth := range authorities {
		t.Run(name, func(t *testing.T) {
			_, err := auth.CanUnlock(ctx, 500)
			// Should not error for reasonable round numbers
			if err != nil {
				t.Errorf("CanUnlock should not error for valid round: %v", err)
			}
		})
	}
}

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

func TestPlaceholderAuthority_CanUnlockRef_AlwaysFalse(t *testing.T) {
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
			canUnlock, err := authority.CanUnlockRef(ref, tc.now)
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if canUnlock {
				t.Error("placeholder authority should never permit unlocking")
			}
		})
	}
}

func TestFakeAuthority_ImplementsInterface(t *testing.T) {
	// Verify FakeAuthority implements Authority interface
	var _ Authority = (*FakeAuthority)(nil)
	
	fake := &FakeAuthority{
		AuthorityName:     "test",
		DefaultRound:      1000,
		DefaultRandomness: []byte("test-randomness"),
		CurrentRound:      2000,
	}

	// Test Name
	if fake.Name() != "test" {
		t.Errorf("expected name 'test', got %s", fake.Name())
	}

	// Test RoundAt
	round, err := fake.RoundAt(time.Now())
	if err != nil {
		t.Fatalf("RoundAt failed: %v", err)
	}
	if round != 1000 {
		t.Errorf("expected round 1000, got %d", round)
	}

	// Test CanUnlock
	canUnlock, err := fake.CanUnlock(context.Background(), 1500)
	if err != nil {
		t.Fatalf("CanUnlock failed: %v", err)
	}
	if !canUnlock {
		t.Error("should be able to unlock round 1500 when current is 2000")
	}
}

