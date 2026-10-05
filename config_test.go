package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func validTestConfig() *Config {
	return &Config{
		ListenPorts:  []int{8080},
		UpstreamAddr: "http://127.0.0.1:3000",
		L7RateLimit:  5.0,
		L7BurstLimit: 10,
	}
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(c *Config) {}, false},
		{"nan rate", func(c *Config) { c.L7RateLimit = math.NaN() }, true},
		{"inf rate", func(c *Config) { c.L7RateLimit = math.Inf(1) }, true},
		{"negative rate", func(c *Config) { c.L7RateLimit = -1 }, true},
		{"absurd rate", func(c *Config) { c.L7RateLimit = 1e10 }, true},
		{"negative l4", func(c *Config) { c.L4ConnLimit = -1 }, true},
		{"negative burst", func(c *Config) { c.L7BurstLimit = -1 }, true},
		{"bad listen port", func(c *Config) { c.ListenPorts = []int{99999} }, true},
		{"bad tcp port", func(c *Config) { c.TcpPorts = []int{0} }, true},
		{"bad upstream scheme", func(c *Config) { c.UpstreamAddr = "ftp://x/" }, true},
		{"upstream no host", func(c *Config) { c.UpstreamAddr = "http://" }, true},
		{"bad blacklist entry", func(c *Config) { c.L3Blacklist = []string{"nope"} }, true},
		{"lowercase country", func(c *Config) { c.BlockedCountries = []string{"cn"} }, true},
		{"long country", func(c *Config) { c.BlockedCountries = []string{"USA"} }, true},
		// Missing .mmdb must NOT fail: the filter degrades gracefully.
		{"missing geoip db ok", func(c *Config) { c.GeoIPDBPath = "/nonexistent/x.mmdb" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validTestConfig()
			tc.mutate(c)
			if err := c.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestConfigGeoIPDirRejected(t *testing.T) {
	dir := t.TempDir()
	c := validTestConfig()
	c.GeoIPDBPath = dir
	if err := c.Validate(); err == nil {
		t.Error("directory geoip_db_path should fail validation")
	}
}

func TestLoadConfigStrictPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, []byte(`{"listen_ports":[8080],"upstream_addr":"http://127.0.0.1:3000"}`), 0644); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"AEGISEDGE_PORT", "AEGISEDGE_PORTS", "AEGISEDGE_TCP_PORTS"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "80abc")
			if _, err := LoadConfig(path); err == nil {
				t.Errorf("%s=%q should fail strict parsing", env, "80abc")
			}
		})
	}
}

func TestLoadConfigTrimsCountries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	if err := os.WriteFile(path, []byte(`{"listen_ports":[8080],"upstream_addr":"http://127.0.0.1:3000"}`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEGISEDGE_BLOCKED_COUNTRIES", " cn, ru ")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.BlockedCountries) != 2 || cfg.BlockedCountries[0] != "CN" || cfg.BlockedCountries[1] != "RU" {
		t.Errorf("countries not trimmed/uppercased: %q", cfg.BlockedCountries)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("trimmed countries should validate: %v", err)
	}
}
