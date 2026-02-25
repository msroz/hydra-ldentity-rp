package config

import (
	"log"
	"os"

	"github.com/ory/common/env"
)

var (
	hydraAdminURL string
	port          = env.Getenv("PORT", "3000")
)

// Load reads and validates configuration from environment variables.
// Must be called before using GetHydraAdminURL.
func Load() {
	hydraAdminURL = os.Getenv("HYDRA_ADMIN_URL")
	if hydraAdminURL == "" {
		log.Fatal("HYDRA_ADMIN_URL environment variable not set")
	}
}

// GetHydraAdminURL returns the Hydra Admin API URL
func GetHydraAdminURL() string {
	return hydraAdminURL
}

// GetPort returns the configured server port
func GetPort() string {
	return port
}
