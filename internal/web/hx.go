package web

import (
	"net/http"
	"strings"
)

// htmx response/request header conventions per API.md §10. The htmx
// JS library reads these on the response to update the page without a
// full reload, and stamps `HX-Request: true` on requests it issues.
const (
	hdrHXRequest  = "HX-Request"
	hdrHXTrigger  = "HX-Trigger"
	hdrHXRedirect = "HX-Redirect"
)

// Well-known event names emitted via HX-Trigger after mutating POSTs.
// Components elsewhere on the page can listen for these and refresh
// themselves without coordinating with the handler.
const (
	EventCertsChanged = "certs:changed"
	EventDeployRan    = "deploy:ran"
)

// IsHXRequest reports whether the request originated from htmx (i.e.
// the page-level fetch added HX-Request: true). Handlers use this to
// decide between a full-page render and a fragment swap at the same
// URL.
func IsHXRequest(r *http.Request) bool {
	return r.Header.Get(hdrHXRequest) == "true"
}

// SetHXTrigger appends events to HX-Trigger so htmx fires the named
// custom events on the document after the swap. Multiple events are
// comma-separated per the htmx spec; calling this twice in one
// response merges into a single header.
func SetHXTrigger(w http.ResponseWriter, events ...string) {
	if len(events) == 0 {
		return
	}
	existing := w.Header().Get(hdrHXTrigger)
	if existing != "" {
		events = append([]string{existing}, events...)
	}
	w.Header().Set(hdrHXTrigger, strings.Join(events, ","))
}

// hxRedirect navigates the client to url. For non-htmx callers this is
// a plain 303 (matches every existing mutating-POST flow). For htmx
// callers it sets HX-Redirect + 200, which makes htmx escape its
// in-place swap and do a full document navigation — the right move
// when the post-mutation page is materially different (e.g. a freshly
// issued cert's detail page).
//
// Trigger events (if any) are emitted on the same response so siblings
// like a header counter can refresh on their way out.
func hxRedirect(w http.ResponseWriter, r *http.Request, url string, triggers ...string) {
	if len(triggers) > 0 {
		SetHXTrigger(w, triggers...)
	}
	if IsHXRequest(r) {
		w.Header().Set(hdrHXRedirect, url)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}
