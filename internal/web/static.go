package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// staticHandler returns an http.Handler for the embedded /static/* assets.
// The handler is composed for use under http.StripPrefix("/static/", ...).
//
// Cache-Control is set to a short public max-age. We don't fingerprint
// asset URLs in v1 so we can't go fully immutable; 5 minutes is short
// enough that an upgrade reaches users quickly and long enough to absorb
// repeat hits within a session.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// fs.Sub on an embed.FS only fails if the path is malformed, which
		// would be a build-time bug.
		panic("staticHandler: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		files.ServeHTTP(w, r)
	})
}
