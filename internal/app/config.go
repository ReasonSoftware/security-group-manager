package app

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
)

// GetConfig returns parsed Configuration from the CONFIG environment variable
func GetConfig() (*Config, error) {
	raw := os.Getenv("CONFIG")
	if raw == "" {
		return new(Config), errors.New("CONFIG environment variable is required")
	}

	c := new(Config)
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		return new(Config), errors.Wrap(err, "error parsing CONFIG")
	}

	if len(c.Protocols) == 0 || len(c.Rules) == 0 {
		return new(Config), errors.New("malformed configuration")
	}

	return c, nil
}
