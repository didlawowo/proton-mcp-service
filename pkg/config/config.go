package config

import (
	"os"
	"path/filepath"
	"strconv"
)

// Config holds all application configuration.
type Config struct {
	APIKey               string
	AllowUnauthenticated bool

	Port     string
	DataDir  string
	LogLevel string

	// ProtonMail credentials (from env or K8s Secret)
	ProtonPassword string

	// AppVersion is the X-Pm-Appversion header sent to Proton. It determines
	// the product scopes granted (mail-only for the bridge, mail+calendar for
	// the web/iOS clients).
	AppVersion string

	// WriteSecret gates all mutating operations (send email, calendar event
	// write). Requests must present it in the X-Write-Key header. If empty,
	// mutating operations are disabled entirely (fail-closed).
	WriteSecret string

	// AllowWritesWithoutKey authorizes mutating operations without any
	// X-Write-Key header (PROTON_ALLOW_WRITES_WITHOUT_KEY=true). It is an
	// explicit opt-out of the write gate: any value other than a true boolean
	// keeps the gate closed.
	AllowWritesWithoutKey bool
}

// Load reads configuration from environment variables.
func Load() *Config {
	return &Config{
		APIKey:               os.Getenv("PROTON_API_KEY"),
		AllowUnauthenticated: parseBool(os.Getenv("PROTON_ALLOW_UNAUTHENTICATED")),
		Port:                 getEnv("PORT", "8080"),
		DataDir:              getEnv("DATA_DIR", "/data"),
		LogLevel:             getEnv("LOG_LEVEL", "info"),
		ProtonPassword:       os.Getenv("PROTON_PASSWORD"),
		AppVersion:           getEnv("PROTON_APP_VERSION", "macos-bridge@3.23.1"),
		WriteSecret:          os.Getenv("PROTON_WRITE_SECRET"),

		AllowWritesWithoutKey: parseBool(os.Getenv("PROTON_ALLOW_WRITES_WITHOUT_KEY")),
	}
}

// parseBool reports whether v is a true boolean ("true", "1", ...). Invalid or
// empty values are false.
func parseBool(v string) bool {
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// SessionPath returns the full path to the session file.
func (c *Config) SessionPath() string {
	return filepath.Join(c.DataDir, "session.json")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
