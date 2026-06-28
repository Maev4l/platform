package config

import (
	"encoding/json"
	"fmt"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
)

type Source struct {
	Name  string `json:"name"`
	Table string `json:"table"`
}

type Config struct {
	Region    string
	Database  string
	Workgroup string
	GeoIPPath string
	Sources   map[string]Source
}

// envMap translates process env var names to koanf keys. Only these are read;
// the env provider's callback returns "" for anything else, which koanf skips.
var envMap = map[string]string{
	"REGION":           "region",
	"ATHENA_DATABASE":  "database",
	"ATHENA_WORKGROUP": "workgroup",
	"GEOIP_DB_PATH":    "geoip_path",
	"LOG_SOURCES":      "log_sources",
}

// Load builds configuration with koanf: defaults overlaid by environment
// variables. LOG_SOURCES is a JSON array of {name,table}.
func Load() (*Config, error) {
	k := koanf.New(".")

	// Layer 1: hard-coded defaults so every key has a baseline value.
	// Errors are ignored on these Load calls: the confmap (static literal map)
	// and env (in-memory) providers have no I/O and cannot realistically fail.
	_ = k.Load(confmap.Provider(map[string]any{
		"region":     "eu-central-1",
		"database":   "monitoring",
		"workgroup":  "monitoring",
		"geoip_path": "./GeoLite2-City.mmdb",
	}, "."), nil)

	// Layer 2: env vars — only the five explicitly mapped vars are read;
	// callback returns "" for everything else so koanf drops them.
	_ = k.Load(env.Provider("", ".", func(s string) string { return envMap[s] }), nil)

	c := &Config{
		Region:    k.String("region"),
		Database:  k.String("database"),
		Workgroup: k.String("workgroup"),
		GeoIPPath: k.String("geoip_path"),
		Sources:   map[string]Source{},
	}

	// Empty / unset LOG_SOURCES is valid (no sources); only non-empty values
	// are parsed, and malformed JSON is a hard error.
	if raw := k.String("log_sources"); raw != "" {
		var list []Source
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return nil, fmt.Errorf("parse LOG_SOURCES: %w", err)
		}
		for _, s := range list {
			c.Sources[s.Name] = s
		}
	}
	return c, nil
}

func (c *Config) Source(name string) (Source, bool) {
	s, ok := c.Sources[name]
	return s, ok
}
