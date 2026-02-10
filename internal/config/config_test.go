package config

import (
	"os"
	"testing"
)

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("DIALTONE_LISTEN_ADDR", ":8080")
	t.Setenv("DIALTONE_DB_URL", "postgres://user@localhost/db")
	t.Setenv("DIALTONE_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("DIALTONE_TLS_KEY", "/tmp/key.pem")
	t.Setenv("DIALTONE_USERNAME_PEPPER", "pepper")
	t.Setenv("DIALTONE_ADMIN_TOKEN", "admin-token")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if cfg.ListenAddr != os.Getenv("DIALTONE_LISTEN_ADDR") {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.DBURL != os.Getenv("DIALTONE_DB_URL") {
		t.Fatalf("DBURL = %q", cfg.DBURL)
	}
	if cfg.TLSCertPath != os.Getenv("DIALTONE_TLS_CERT") {
		t.Fatalf("TLSCertPath = %q", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != os.Getenv("DIALTONE_TLS_KEY") {
		t.Fatalf("TLSKeyPath = %q", cfg.TLSKeyPath)
	}
	if cfg.UsernamePepper != os.Getenv("DIALTONE_USERNAME_PEPPER") {
		t.Fatalf("UsernamePepper = %q", cfg.UsernamePepper)
	}
	if cfg.AdminToken != os.Getenv("DIALTONE_ADMIN_TOKEN") {
		t.Fatalf("AdminToken = %q", cfg.AdminToken)
	}
}

func TestValidate_RequiredFields(t *testing.T) {
	cfg := Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing fields")
	}

	cfg = Config{ListenAddr: ":8080"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing db url")
	}

	cfg = Config{ListenAddr: ":8080", DBURL: "postgres://"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing username pepper")
	}

	cfg = Config{ListenAddr: ":8080", DBURL: "postgres://", UsernamePepper: "pepper"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing admin token")
	}
}

func TestValidate_TLSMismatch(t *testing.T) {
	cfg := Config{
		ListenAddr:     ":8080",
		DBURL:          "postgres://",
		UsernamePepper: "pepper",
		AdminToken:     "admin",
		TLSCertPath:    "/tmp/cert.pem",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for tls mismatch")
	}

	cfg.TLSCertPath = ""
	cfg.TLSKeyPath = "/tmp/key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for tls mismatch")
	}
}

func TestValidate_OK(t *testing.T) {
	cfg := Config{
		ListenAddr:     ":8080",
		DBURL:          "postgres://",
		UsernamePepper: "pepper",
		AdminToken:     "admin",
		TLSCertPath:    "/tmp/cert.pem",
		TLSKeyPath:     "/tmp/key.pem",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
