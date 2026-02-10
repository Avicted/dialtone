package securestore

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestNewFieldCrypto_InvalidKey(t *testing.T) {
	_, err := NewFieldCrypto([]byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestEncryptDecryptString_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	ciphertext, err := fc.EncryptString("hello")
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	if ciphertext == "" {
		t.Fatal("EncryptString() returned empty ciphertext")
	}

	plaintext, err := fc.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}
	if plaintext != "hello" {
		t.Fatalf("DecryptString() = %q, want %q", plaintext, "hello")
	}
}

func TestEncryptString_Empty(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	ciphertext, err := fc.EncryptString("")
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	if ciphertext != "" {
		t.Fatalf("EncryptString() = %q, want empty", ciphertext)
	}
}

func TestDecryptString_Empty(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	plaintext, err := fc.DecryptString("")
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}
	if plaintext != "" {
		t.Fatalf("DecryptString() = %q, want empty", plaintext)
	}
}

func TestDecryptString_InvalidBase64(t *testing.T) {
	key := bytes.Repeat([]byte{0x04}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	_, err = fc.DecryptString("not-base64")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestHashString_Stable(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	h1 := fc.HashString("value")
	h2 := fc.HashString("value")
	if h1 == "" || h2 == "" {
		t.Fatal("HashString() returned empty")
	}
	if h1 != h2 {
		t.Fatalf("HashString() values differ: %q vs %q", h1, h2)
	}
}

func TestEncryptString_NonDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x06}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	ct1, err := fc.EncryptString("same")
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	ct2, err := fc.EncryptString("same")
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}

	if ct1 == ct2 {
		t.Fatal("expected different ciphertext for same plaintext")
	}
	if _, err := base64.StdEncoding.DecodeString(ct1); err != nil {
		t.Fatalf("ciphertext not base64: %v", err)
	}
}
