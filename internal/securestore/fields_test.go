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

func TestDecryptString_TamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	ct, err := fc.EncryptString("hello")
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}

	// Tamper with the ciphertext
	raw, _ := base64.StdEncoding.DecodeString(ct)
	if len(raw) > 12 {
		raw[12] ^= 0xff
	}
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = fc.DecryptString(tampered)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestDecryptString_TooShortCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x08}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	// Encode a very short byte sequence
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	_, err = fc.DecryptString(short)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestHashString_Empty(t *testing.T) {
	key := bytes.Repeat([]byte{0x09}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	h := fc.HashString("")
	if h != "" {
		t.Fatalf("HashString('') = %q, want empty", h)
	}
}

func TestHashString_DifferentInputs(t *testing.T) {
	key := bytes.Repeat([]byte{0x0a}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	h1 := fc.HashString("value1")
	h2 := fc.HashString("value2")
	if h1 == h2 {
		t.Fatal("HashString should produce different hashes for different inputs")
	}
}

func TestNewFieldCrypto_ValidKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}
	if fc == nil {
		t.Fatal("NewFieldCrypto() returned nil")
	}
}

func TestEncryptDecrypt_LongString(t *testing.T) {
	key := bytes.Repeat([]byte{0x0c}, keySize)
	fc, err := NewFieldCrypto(key)
	if err != nil {
		t.Fatalf("NewFieldCrypto() error = %v", err)
	}

	longStr := string(bytes.Repeat([]byte{'A'}, 10000))
	ct, err := fc.EncryptString(longStr)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	pt, err := fc.DecryptString(ct)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}
	if pt != longStr {
		t.Fatal("roundtrip mismatch for long string")
	}
}

func TestDecryptString_WrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x0d}, keySize)
	key2 := bytes.Repeat([]byte{0x0e}, keySize)

	fc1, _ := NewFieldCrypto(key1)
	fc2, _ := NewFieldCrypto(key2)

	ct, _ := fc1.EncryptString("secret")
	_, err := fc2.DecryptString(ct)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}
