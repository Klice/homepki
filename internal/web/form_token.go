package web

import (
	"errors"
	"net/http"

	"github.com/Klice/homepki/internal/store"
)

// formTokenName is the form field name for the per-form replay-protection
// token. Distinct from csrf_token (managed by gorilla/csrf in csrf.go).
const formTokenName = "form_token"

// formTokenState tells the POST handler what to do based on the submitted
// token's persisted state (per API.md §2.7.1).
type formTokenState struct {
	// Token is the verified token string, ready to pass to
	// store.IssueCertWithToken (or any other "atomic combinator").
	Token string
	// Replay is true when the token was already consumed by a previous
	// successful submission. The handler must short-circuit and 303 to
	// ResultURL without re-executing.
	Replay bool
	// ResultURL is the target of the replay redirect. Only set when Replay
	// is true.
	ResultURL string
}

// validateFormToken inspects the submitted token. The four return shapes
// drive distinct handler responses:
//
//	state, nil  state.Replay==false   → execute the operation
//	state, nil  state.Replay==true    → 303 to state.ResultURL (replay)
//	nil, nil                          → 400 "stale form" (token missing/expired)
//	nil, err                          → DB error, 500
func (s *Server) validateFormToken(token string) (*formTokenState, error) {
	if token == "" {
		return nil, nil
	}
	row, err := store.LookupIdemToken(s.db, token)
	if errors.Is(err, store.ErrIdemTokenNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &formTokenState{Token: token}
	if row.UsedAt != nil {
		out.Replay = true
		if row.ResultURL != nil {
			out.ResultURL = *row.ResultURL
		}
	}
	return out, nil
}

// staleFormResponse writes the 400 response for a missing/expired token
// per API.md §2.7.1.
func staleFormResponse(w http.ResponseWriter) {
	http.Error(w, "stale form — please reload", http.StatusBadRequest)
}
