// Package config loads and combines airjail configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

// DefaultConnectTimeout bounds outbound connection establishment by default.
const DefaultConnectTimeout = 5 * time.Second

// Config is the effective user configuration.
type Config struct {
	Allow                  []string      `yaml:"allow"`
	Block                  []string      `yaml:"block"`
	Log                    string        `yaml:"log"`
	Proxy                  string        `yaml:"proxy"`
	ConnectTimeout         time.Duration `yaml:"connect_timeout"`
	TransparentFallback    bool          `yaml:"transparent_fallback"`
	RestrictUnixSockets    bool          `yaml:"restrict_sockets"`
	AllowUnresolvedRules   bool          `yaml:"allow_unresolved_rules"`
	KeepUnsafeCapabilities []string      `yaml:"keep_unsafe_capabilities"`
}

// Default returns the default configuration.
func Default() Config {
	return Config{
		ConnectTimeout:      DefaultConnectTimeout,
		TransparentFallback: true,
	}
}

// Load reads a strict YAML configuration file.
func Load(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)

	loaded := Default()

	err = decoder.Decode(&loaded)
	if errors.Is(err, io.EOF) {
		return loaded, nil
	}

	if err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	var extra any

	err = decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		if err != nil {
			return Config{}, fmt.Errorf("decode trailing config document %q: %w", path, err)
		}

		return Config{}, fmt.Errorf("decode config %q: multiple YAML documents are not supported", path)
	}

	return loaded, nil
}
