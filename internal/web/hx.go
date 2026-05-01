package web

import (
	"net/http"
	"strings"
)

const (
	hdrHXRequest  = "HX-Request"
	hdrHXTrigger  = "HX-Trigger"
	hdrHXRedirect = "HX-Redirect"
)

const (
	EventCertsChanged = "certs:changed"
	EventDeployRan    = "deploy:ran"
)

func IsHXRequest(r *http.Request) bool {
	return r.Header.Get(hdrHXRequest) == "true"
}

// SetHXTrigger merges events into HX-Trigger so calling it twice in
// one response produces a single comma-separated header.
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

// hxRedirect navigates the client to url: HX-Redirect + 200 for htmx,
// 303 otherwise. Trigger events are emitted on the same response.
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
