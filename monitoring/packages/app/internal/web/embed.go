package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var dist embed.FS

// FS returns the embedded SPA build rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// Handler serves the SPA, falling back to index.html for client-side routes.
func Handler() http.Handler {
	root := FS()
	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Stat(root, trimLeadingSlash(r.URL.Path)); err != nil {
			// not a real file → SPA entrypoint
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func trimLeadingSlash(p string) string {
	if p == "/" || p == "" {
		return "index.html"
	}
	if p[0] == '/' {
		return p[1:]
	}
	return p
}
