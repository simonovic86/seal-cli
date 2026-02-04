package timeauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test helpers to avoid import cycle with testutil

func newTestDrandAuthority(currentRound uint64) *DrandAuthority {
	fakeHTTP := &fakeHTTPDoer{
		Responses: map[string]*http.Response{
			"/info":          makeDrandInfoResponse(),
			"/public/latest": makeDrandPublicResponse(currentRound),
		},
	}

	return NewDrandAuthorityWithDeps(fakeHTTP, &fakeTimelockBox{})
}

type fakeHTTPDoer struct {
	Responses map[string]*http.Response
	Errors    map[string]error
}

func (f *fakeHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	for suffix, err := range f.Errors {
		if strings.HasSuffix(path, suffix) {
			return nil, err
		}
	}
	for suffix, resp := range f.Responses {
		if strings.HasSuffix(path, suffix) {
			return cloneResponse(resp), nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

func cloneResponse(resp *http.Response) *http.Response {
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return &http.Response{
		StatusCode: resp.StatusCode,
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}
}

func makeDrandInfoResponse() *http.Response {
	info := struct {
		Period      int    `json:"period"`
		GenesisTime int64  `json:"genesis_time"`
		Hash        string `json:"hash"`
		GroupHash   string `json:"groupHash"`
		SchemeID    string `json:"schemeID"`
		BeaconID    string `json:"beaconID"`
	}{
		Period:      3,
		GenesisTime: 1677685200,
		Hash:        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
		SchemeID:    "bls-unchained-on-g1",
		BeaconID:    "quicknet",
	}
	body, _ := json.Marshal(info)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func makeDrandPublicResponse(round uint64) *http.Response {
	resp := struct {
		Round      uint64 `json:"round"`
		Randomness string `json:"randomness"`
	}{
		Round:      round,
		Randomness: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

type fakeTimelockBox struct{}

func (f *fakeTimelockBox) Encrypt(dek []byte, targetRound uint64) (string, error) {
	return "FAKE_TLOCK:" + string(dek), nil
}

func (f *fakeTimelockBox) Decrypt(ciphertextB64 string) ([]byte, error) {
	if strings.HasPrefix(ciphertextB64, "FAKE_TLOCK:") {
		return []byte(strings.TrimPrefix(ciphertextB64, "FAKE_TLOCK:")), nil
	}
	return nil, io.ErrUnexpectedEOF
}

func TestDrandAuthority_Name(t *testing.T) {
	authority := newTestDrandAuthority(1000)
	
	if authority.Name() != "drand" {
		t.Errorf("expected name 'drand', got %s", authority.Name())
	}
}

func TestDrandAuthority_KeyReference_Structure(t *testing.T) {
	// Test that Lock produces a valid DrandKeyReference structure
	authority := newTestDrandAuthority(1000)
	
	// Use a future time for testing
	unlockTime := time.Now().UTC().Add(24 * time.Hour)
	
	ref, err := authority.Lock(unlockTime)
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Parse the reference
	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(ref), &drandRef); err != nil {
		t.Fatalf("key reference should be valid JSON: %v", err)
	}

	// Verify structure
	if drandRef.Network == "" {
		t.Error("network should not be empty")
	}

	if drandRef.TargetRound == 0 {
		t.Error("target round should not be zero")
	}

	if drandRef.Network != "quicknet" {
		t.Errorf("expected network 'quicknet', got %s", drandRef.Network)
	}
}

func TestDrandAuthority_CanUnlock_Logic(t *testing.T) {
	testCases := []struct {
		name         string
		ref          DrandKeyReference
		currentRound uint64
		shouldError  bool
		canUnlock    bool
	}{
		{
			name: "valid reference, round reached",
			ref: DrandKeyReference{
				Network:     "quicknet",
				TargetRound: 1000,
			},
			currentRound: 1500,
			shouldError:  false,
			canUnlock:    true,
		},
		{
			name: "valid reference, round not reached",
			ref: DrandKeyReference{
				Network:     "quicknet",
				TargetRound: 2000,
			},
			currentRound: 1500,
			shouldError:  false,
			canUnlock:    false,
		},
		{
			name: "wrong network",
			ref: DrandKeyReference{
				Network:     "wrong-network",
				TargetRound: 1000,
			},
			currentRound: 1500,
			shouldError:  true,
			canUnlock:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authority := newTestDrandAuthority(tc.currentRound)
			
			refJSON, _ := json.Marshal(tc.ref)
			keyRef := KeyReference(refJSON)
			
			canUnlock, err := authority.CanUnlockRef(keyRef, time.Now())
			
			if tc.shouldError && err == nil {
				t.Error("expected error, got nil")
			}
			
			if !tc.shouldError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tc.shouldError && canUnlock != tc.canUnlock {
				t.Errorf("expected canUnlock=%v, got %v", tc.canUnlock, canUnlock)
			}
		})
	}
}

func TestDrandAuthority_InvalidKeyReference(t *testing.T) {
	authority := newTestDrandAuthority(1000)
	
	// Invalid JSON
	invalidRef := KeyReference("not-valid-json")
	
	canUnlock, err := authority.CanUnlockRef(invalidRef, time.Now())
	if err == nil {
		t.Error("expected error for invalid key reference")
	}
	
	if canUnlock {
		t.Error("should not be able to unlock with invalid reference")
	}
	
	if !strings.Contains(err.Error(), "invalid drand key reference") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDrandAuthority_NetworkFailure_DoesNotUnlock(t *testing.T) {
	// Test with HTTP client that returns errors
	fakeHTTP := &fakeHTTPDoer{
		Errors: map[string]error{
			"/public/latest": io.ErrUnexpectedEOF,
		},
		Responses: map[string]*http.Response{
			"/info": makeDrandInfoResponse(),
		},
	}
	
	authority := NewDrandAuthorityWithDeps(fakeHTTP, &fakeTimelockBox{})
	
	ref := DrandKeyReference{
		Network:     "quicknet",
		TargetRound: 1000,
	}
	
	refJSON, _ := json.Marshal(ref)
	keyRef := KeyReference(refJSON)
	
	canUnlock, err := authority.CanUnlockRef(keyRef, time.Now())
	
	// Network failure should return error
	if err == nil {
		t.Error("expected error on network failure")
	}
	
	// Should NOT unlock on network failure
	if canUnlock {
		t.Error("should not unlock on network failure")
	}
}

func TestDrandKeyReference_Serialization(t *testing.T) {
	ref := DrandKeyReference{
		Network:     "quicknet",
		TargetRound: 12345678,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Unmarshal back
	var decoded DrandKeyReference
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify fields
	if decoded.Network != ref.Network {
		t.Errorf("Network mismatch: got %s, want %s", decoded.Network, ref.Network)
	}

	if decoded.TargetRound != ref.TargetRound {
		t.Errorf("TargetRound mismatch: got %d, want %d", decoded.TargetRound, ref.TargetRound)
	}
}

func TestDrandAuthority_RoundCalculation(t *testing.T) {
	// Test the round calculation logic with known values
	// Our fake drand has period=3 and genesis_time=1677685200
	
	authority := newTestDrandAuthority(1000)
	
	// Get info from our fake
	info, err := authority.FetchInfo()
	if err != nil {
		t.Fatalf("FetchInfo failed: %v", err)
	}

	// Create a time based on genesis + known rounds
	// Round N starts at: genesis_time + (N * period)
	testRound := uint64(1000)
	testTime := time.Unix(info.GenesisTime+int64(testRound)*int64(info.Period), 0)
	
	ref, err := authority.Lock(testTime)
	if err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(ref), &drandRef); err != nil {
		t.Fatalf("failed to parse reference: %v", err)
	}

	// Target round should be at or slightly after testRound
	// (due to rounding up to ensure unlock time is reached)
	if drandRef.TargetRound < testRound {
		t.Errorf("target round should be >= %d, got %d", testRound, drandRef.TargetRound)
	}

	if drandRef.TargetRound > testRound+1 {
		t.Errorf("target round should be close to %d, got %d", testRound, drandRef.TargetRound)
	}
}
