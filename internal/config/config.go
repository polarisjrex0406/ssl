package config

import (
	"fmt"
	"sync"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
)

var (
	instance *Config
	once     sync.Once
)

// LoadConfig loads the configuration from .env and command-line flags.
func LoadConfig() (*Config, error) {
	var cfg Config
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}
	fp := flags.NewParser(&cfg, flags.Default)
	// Parse flags
	if _, err := fp.Parse(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetConfig returns the singleton instance of Config.
func GetConfig() (*Config, error) {
	var err error
	once.Do(func() {
		instance, err = LoadConfig()
	})
	return instance, err
}

type Config struct {
	Command struct {
		Migrate bool `long:"migrate"`
		Seed    bool `long:"seed"`
	}

	Server struct {
		Port int `long:"server-port" env:"SERVER_PORT" default:"8080"`
		Rate struct {
			Period time.Duration `long:"server-rate-period" env:"SERVER_RATE_PERIOD" default:"1m" description:""`
			Limit  int64         `long:"server-rate-limit" env:"SERVER_RATE_LIMIT" default:"60" description:""`
		}
		Auth struct {
			Header string `long:"server-auth-header" env:"SERVER_AUTH_HEADER" default:"X-XODUXCRT-AUTH-TOKEN"`
			Token  string `long:"server-auth-token" env:"SERVER_AUTH_TOKEN" default:""`
		}
		AllowedIPs string `long:"server-allowed_ips" env:"SERVER_ALLOWED_IPS" default:""`
	}

	Postgres struct {
		DBName   string `long:"postgres-db-name" env:"POSTGRES_DB_NAME" default:""`
		User     string `long:"postgres-user" env:"POSTGRES_USER" default:""`
		Password string `long:"postgres-password" env:"POSTGRES_PASSWORD"`
		Host     string `long:"postgres-host" env:"POSTGRES_HOST" default:"localhost"`
		Port     int    `long:"postgres-port" env:"POSTGRES_PORT" default:"5432"`
		SSLMode  string `long:"postgres-ssl-mode" env:"POSTGRES_SSL_MODE" default:"disable"`
	}
}
