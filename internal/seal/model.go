package seal

import "time"

const (
	MaxInputSize = 10 * 1024 * 1024 // 10MB
)

type InputSource int

const (
	InputSourceFile InputSource = iota
	InputSourceStdin
)

func (i InputSource) String() string {
	if i == InputSourceFile {
		return "file"
	}
	return "stdin"
}

// KeyReference is an opaque reference to a time-locked encryption key.
type KeyReference string

// SealedItem represents metadata for a sealed item.
type SealedItem struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	UnlockTime    time.Time `json:"unlock_time"`
	InputType     string    `json:"input_type"`
	OriginalPath  string    `json:"original_path,omitempty"`
	TimeAuthority string    `json:"time_authority"`
	CreatedAt     time.Time `json:"created_at"`
	Algorithm     string    `json:"algorithm"`
	Nonce         string    `json:"nonce"`
	KeyRef        string    `json:"key_ref"`
	DEKTlockB64   string    `json:"dek_tlock_b64,omitempty"` // tlock-encrypted DEK (base64)
}

// DrandKeyReference contains drand-specific information for time-locked keys.
type DrandKeyReference struct {
	Network     string `json:"network"`
	TargetRound uint64 `json:"target_round"`
}
