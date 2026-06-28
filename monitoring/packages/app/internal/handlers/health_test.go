package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/health", Health)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != `{"status":"ok"}` {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}
