package config

import (
	"encoding/json"
	"fmt"
	"os"
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

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() (*Config, error) {
	c := &Config{
		Region:    env("REGION", "eu-central-1"),
		Database:  env("ATHENA_DATABASE", "monitoring"),
		Workgroup: env("ATHENA_WORKGROUP", "monitoring"),
		GeoIPPath: env("GEOIP_DB_PATH", "./GeoLite2-City.mmdb"),
		Sources:   map[string]Source{},
	}
	var list []Source
	if err := json.Unmarshal([]byte(os.Getenv("LOG_SOURCES")), &list); err != nil {
		return nil, fmt.Errorf("parse LOG_SOURCES: %w", err)
	}
	for _, s := range list {
		c.Sources[s.Name] = s
	}
	return c, nil
}

func (c *Config) Source(name string) (Source, bool) {
	s, ok := c.Sources[name]
	return s, ok
}
