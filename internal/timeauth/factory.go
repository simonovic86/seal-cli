package timeauth

// NewDefaultAuthority creates the default production time authority.
// Currently returns a drand quicknet authority.
// This centralizes authority construction and allows future configuration expansion.
func NewDefaultAuthority() Authority {
	return NewDefaultDrandAuthority()
}
