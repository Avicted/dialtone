package config

import (
	"errors"
	"os"
)

type Config struct {
	ListenAddr  string
	DBURL       string
	TLSCertPath string
	TLSKeyPath  string
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:  ":8080",
		DBURL:       os.Getenv("DIALTONE_DB_URL"),
		TLSCertPath: os.Getenv("DIALTONE_TLS_CERT"),
		TLSKeyPath:  os.Getenv("DIALTONE_TLS_KEY"),
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
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		return errors.New("both tls cert and key are required when enabling tls")
	}
	return nil
}
