package config

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/Avicted/dialtone/internal/crypto"
)

type Config struct {
	ListenAddr     string
	DBURL          string
	TLSCertPath    string
	TLSKeyPath     string
	UsernamePepper string
	ChannelKey     string
	AdminToken     string
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:     ":8080",
		DBURL:          os.Getenv("DIALTONE_DB_URL"),
		TLSCertPath:    os.Getenv("DIALTONE_TLS_CERT"),
		TLSKeyPath:     os.Getenv("DIALTONE_TLS_KEY"),
		UsernamePepper: os.Getenv("DIALTONE_USERNAME_PEPPER"),
		ChannelKey:     os.Getenv("DIALTONE_CHANNEL_KEY"),
		AdminToken:     os.Getenv("DIALTONE_ADMIN_TOKEN"),
	}

	if v := os.Getenv("DIALTONE_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen addr is required")
	}
	if c.DBURL == "" {
		return errors.New("db url is required")
	}
	if c.UsernamePepper == "" {
		return errors.New("username pepper is required")
	}
	if c.ChannelKey == "" {
		return errors.New("channel key is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(c.ChannelKey)
	if err != nil {
		return errors.New("channel key must be base64")
	}
	if len(decoded) != crypto.KeySize {
		return errors.New("channel key must be 32 bytes")
	}
	if c.AdminToken == "" {
		return errors.New("admin token is required")
	}
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		return errors.New("both tls cert and key are required when enabling tls")
	}
	return nil
}
