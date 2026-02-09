package config

import (
	"encoding/base64"
	"errors"
	"os"
)

type Config struct {
	ListenAddr  string
	DBURL       string
	TLSCertPath string
	TLSKeyPath  string
	MasterKey   []byte
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:  ":8080",
		DBURL:       os.Getenv("DIALTONE_DB_URL"),
		TLSCertPath: os.Getenv("DIALTONE_TLS_CERT"),
		TLSKeyPath:  os.Getenv("DIALTONE_TLS_KEY"),
	}

	if v := os.Getenv("DIALTONE_MASTER_KEY"); v != "" {
		key, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return Config{}, errors.New("master key must be base64")
		}
		cfg.MasterKey = key
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
	if len(c.MasterKey) != 32 {
		return errors.New("master key must be 32 bytes (base64-encoded)")
	}
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		return errors.New("both tls cert and key are required when enabling tls")
	}
	return nil
}
