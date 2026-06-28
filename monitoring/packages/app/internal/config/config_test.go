package config

import (
	"os"
	"testing"
)

func TestLoadDefaultsAndSources(t *testing.T) {
	os.Unsetenv("REGION")
	os.Setenv("LOG_SOURCES", `[{"name":"bl-site","table":"bl_site"}]`)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Region != "eu-central-1" || c.Database != "platform-monitoring" || c.Workgroup != "platform-monitoring" {
		t.Fatalf("bad defaults: %+v", c)
	}
	if s, ok := c.Source("bl-site"); !ok || s.Table != "bl_site" {
		t.Fatalf("source lookup failed: %+v ok=%v", s, ok)
	}
}

func TestLoadBadJSON(t *testing.T) {
	os.Setenv("LOG_SOURCES", "nope")
	if _, err := Load(); err == nil {
		t.Fatal("expected error")
	}
}
