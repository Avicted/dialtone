package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if kp.Private == nil {
		t.Fatal("private key is nil")
	}
	if kp.Public == nil {
		t.Fatal("public key is nil")
	}
	if len(kp.Public.Bytes()) != 32 {
		t.Fatalf("public key length = %d, want 32", len(kp.Public.Bytes()))
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if bytes.Equal(kp1.Private.Bytes(), kp2.Private.Bytes()) {
		t.Fatal("two generated key pairs should not be identical")
	}
}

func TestPublicKeyRoundtrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	encoded := PublicKeyToBase64(kp.Public)
	decoded, err := PublicKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("PublicKeyFromBase64() error = %v", err)
	}
	if !bytes.Equal(kp.Public.Bytes(), decoded.Bytes()) {
		t.Fatal("public key roundtrip mismatch")
	}
}

func TestPrivateKeyRoundtrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	encoded := PrivateKeyToBase64(kp.Private)
	decoded, err := PrivateKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("PrivateKeyFromBase64() error = %v", err)
	}
	if !bytes.Equal(kp.Private.Bytes(), decoded.Bytes()) {
		t.Fatal("private key roundtrip mismatch")
	}
}

func TestPublicKeyFromBase64_InvalidBase64(t *testing.T) {
	_, err := PublicKeyFromBase64("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestPublicKeyFromBase64_WrongLength(t *testing.T) {
	// A valid base64 string but wrong key length.
	_, err := PublicKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("short")))
	if err == nil {
		t.Fatal("expected error for wrong-length key bytes")
	}
}

func TestPrivateKeyFromBase64_Invalid(t *testing.T) {
	_, err := PrivateKeyFromBase64("not-valid")
	if err == nil {
		t.Fatal("expected error for invalid base64 private key")
	}
}

func TestPrivateKeyFromBase64_WrongLength(t *testing.T) {
	// Valid base64 but wrong key length
	_, err := PrivateKeyFromBase64(base64.StdEncoding.EncodeToString([]byte("short")))
	if err == nil {
		t.Fatal("expected error for wrong-length private key")
	}
}

func TestDecryptFromPeer_NilKeys(t *testing.T) {
	kp, _ := GenerateKeyPair()

	_, err := DecryptFromPeer(nil, kp.Public, "dGVzdA==")
	if err == nil {
		t.Fatal("expected error for nil private key")
	}

	_, err = DecryptFromPeer(kp.Private, (*ecdh.PublicKey)(nil), "dGVzdA==")
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestEncrypt_DifferentKeys(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key2[0] = 1

	ct1, err := Encrypt(key1, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	ct2, err := Encrypt(key2, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Must be able to decrypt with correct key
	pt1, _ := Decrypt(key1, ct1)
	pt2, _ := Decrypt(key2, ct2)
	if string(pt1) != "hello" || string(pt2) != "hello" {
		t.Fatal("decrypt failed with correct keys")
	}
}

func TestDeriveSharedKey_Length(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	key, err := DeriveSharedKey(alice.Private, bob.Public, nil)
	if err != nil {
		t.Fatalf("DeriveSharedKey() error = %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("key length = %d, want %d", len(key), KeySize)
	}
}

func TestEncryptForPeer_EmptyMessage(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	encoded, err := EncryptForPeer(alice.Private, bob.Public, []byte{})
	if err != nil {
		t.Fatalf("EncryptForPeer() error = %v", err)
	}

	pt, err := DecryptFromPeer(bob.Private, alice.Public, encoded)
	if err != nil {
		t.Fatalf("DecryptFromPeer() error = %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
	}
}

func TestDecryptFromPeer_TamperedCiphertext(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	encoded, err := EncryptForPeer(alice.Private, bob.Public, []byte("secret"))
	if err != nil {
		t.Fatalf("EncryptForPeer() error = %v", err)
	}

	// Tamper with the base64 encoded ciphertext
	raw, _ := base64.StdEncoding.DecodeString(encoded)
	if len(raw) > NonceSize {
		raw[NonceSize] ^= 0xff
	}
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = DecryptFromPeer(bob.Private, alice.Public, tampered)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestDeriveSharedKey_Symmetry(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	keyAB, err := DeriveSharedKey(alice.Private, bob.Public, nil)
	if err != nil {
		t.Fatalf("DeriveSharedKey(alice, bob) error = %v", err)
	}
	keyBA, err := DeriveSharedKey(bob.Private, alice.Public, nil)
	if err != nil {
		t.Fatalf("DeriveSharedKey(bob, alice) error = %v", err)
	}

	if !bytes.Equal(keyAB, keyBA) {
		t.Fatal("shared keys should be symmetric")
	}
	if len(keyAB) != KeySize {
		t.Fatalf("shared key length = %d, want %d", len(keyAB), KeySize)
	}
}

func TestDeriveSharedKey_DifferentPeers(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	charlie, _ := GenerateKeyPair()

	keyAB, _ := DeriveSharedKey(alice.Private, bob.Public, nil)
	keyAC, _ := DeriveSharedKey(alice.Private, charlie.Public, nil)

	if bytes.Equal(keyAB, keyAC) {
		t.Fatal("shared keys for different peers should differ")
	}
}

func TestDeriveSharedKey_WithSalt(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	keyNoSalt, _ := DeriveSharedKey(alice.Private, bob.Public, nil)
	keySalted, _ := DeriveSharedKey(alice.Private, bob.Public, []byte("some-salt"))

	if bytes.Equal(keyNoSalt, keySalted) {
		t.Fatal("salted and unsalted keys should differ")
	}

	// Same salt should produce same key.
	keySalted2, _ := DeriveSharedKey(alice.Private, bob.Public, []byte("some-salt"))
	if !bytes.Equal(keySalted, keySalted2) {
		t.Fatal("same salt should produce same derived key")
	}
}

func TestDeriveSharedKey_NilKeys(t *testing.T) {
	kp, _ := GenerateKeyPair()

	_, err := DeriveSharedKey(nil, kp.Public, nil)
	if err == nil {
		t.Fatal("expected error for nil private key")
	}

	_, err = DeriveSharedKey(kp.Private, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello dialtone")
	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertext must be longer than plaintext (nonce + tag overhead).
	if len(ct) <= len(plaintext) {
		t.Fatalf("ciphertext (%d bytes) should be longer than plaintext (%d bytes)", len(ct), len(plaintext))
	}

	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", pt, plaintext)
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, KeySize)
	ct, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	_, err := Encrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	_, err := Decrypt([]byte("short"), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDecrypt_TruncatedCiphertext(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := Decrypt(key, make([]byte, NonceSize-1))
	if err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := make([]byte, KeySize)
	ct, _ := Encrypt(key, []byte("secret"))

	// Flip a bit in the sealed portion.
	ct[NonceSize] ^= 0xff

	_, err := Decrypt(key, ct)
	if err == nil {
		t.Fatal("expected decryption failure for tampered ciphertext")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key2[0] = 0xff

	ct, _ := Encrypt(key1, []byte("secret"))
	_, err := Decrypt(key2, ct)
	if err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

func TestEncrypt_NonDeterministic(t *testing.T) {
	key := make([]byte, KeySize)
	plaintext := []byte("same message")

	ct1, _ := Encrypt(key, plaintext)
	ct2, _ := Encrypt(key, plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertexts")
	}
}

func TestEncryptForPeer_DecryptFromPeer(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	plaintext := []byte("hello from alice to bob")

	encoded, err := EncryptForPeer(alice.Private, bob.Public, plaintext)
	if err != nil {
		t.Fatalf("EncryptForPeer() error = %v", err)
	}

	// Should be valid base64.
	if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
		t.Fatalf("EncryptForPeer() result is not valid base64: %v", err)
	}

	pt, err := DecryptFromPeer(bob.Private, alice.Public, encoded)
	if err != nil {
		t.Fatalf("DecryptFromPeer() error = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("DecryptFromPeer() = %q, want %q", pt, plaintext)
	}
}

func TestDecryptFromPeer_InvalidBase64(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	_, err := DecryptFromPeer(bob.Private, alice.Public, "!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecryptFromPeer_WrongSender(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	charlie, _ := GenerateKeyPair()

	encoded, _ := EncryptForPeer(alice.Private, bob.Public, []byte("secret"))

	// Charlie tries to decrypt as if he were Alice.
	_, err := DecryptFromPeer(bob.Private, charlie.Public, encoded)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong sender key")
	}
}

func TestKeyEncodeDecode_Integration(t *testing.T) {
	// Full round-trip: generate -> encode -> decode -> encrypt -> decrypt.
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Simulate sending public keys over the wire.
	alicePubB64 := PublicKeyToBase64(alice.Public)
	bobPubB64 := PublicKeyToBase64(bob.Public)

	alicePub, _ := PublicKeyFromBase64(alicePubB64)
	bobPub, _ := PublicKeyFromBase64(bobPubB64)

	// Alice encrypts for Bob using the decoded public key.
	msg := []byte("integration test message")
	encoded, err := EncryptForPeer(alice.Private, bobPub, msg)
	if err != nil {
		t.Fatalf("EncryptForPeer() error = %v", err)
	}

	// Bob decrypts from Alice using the decoded public key.
	pt, err := DecryptFromPeer(bob.Private, alicePub, encoded)
	if err != nil {
		t.Fatalf("DecryptFromPeer() error = %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("got %q, want %q", pt, msg)
	}
}

func TestEncryptForPeer_NilKeys(t *testing.T) {
	kp, _ := GenerateKeyPair()

	_, err := EncryptForPeer(nil, kp.Public, []byte("test"))
	if err == nil {
		t.Fatal("expected error for nil private key")
	}

	_, err = EncryptForPeer(kp.Private, (*ecdh.PublicKey)(nil), []byte("test"))
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestLargeMessage(t *testing.T) {
	key := make([]byte, KeySize)
	plaintext := []byte(strings.Repeat("A", 1<<16))

	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	pt, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatal("large message roundtrip failed")
	}
}
