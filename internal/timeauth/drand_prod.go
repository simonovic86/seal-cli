//go:build !testmode

package timeauth

import "net/http"

// NewDefaultDrandAuthority creates a DrandAuthority for production use.
func NewDefaultDrandAuthority() *DrandAuthority {
	return NewDrandAuthorityWithDeps(http.DefaultClient, nil)
}
