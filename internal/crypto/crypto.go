// Package crypto provides end-to-end encryption primitives using only the Go
// standard library crypto packages. It implements X25519 ECDH key exchange,
// HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// NonceSize is the byte length of the GCM nonce (96 bits).
	NonceSize = 12
	// KeySize is the byte length of the AES-256 key.
	KeySize = 32
)

var (
	ErrInvalidKey        = errors.New("crypto: invalid key")
	ErrDecryptionFailed  = errors.New("crypto: decryption failed")
	ErrInvalidCiphertext = errors.New("crypto: invalid ciphertext")
)

// hkdfInfo is the context string bound into derived keys.
var hkdfInfo = []byte("dialtone-e2e-v1")

// KeyPair holds an X25519 private/public key pair.
type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// GenerateKeyPair creates a new X25519 key pair from crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}

// PublicKeyToBase64 encodes a public key as standard base64.
func PublicKeyToBase64(pub *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

// PrivateKeyToBase64 encodes a private key as standard base64.
func PrivateKeyToBase64(priv *ecdh.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Bytes())
}

// PublicKeyFromBase64 decodes a base64-encoded X25519 public key.
func PublicKeyFromBase64(encoded string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %v", ErrInvalidKey, err)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse public key: %v", ErrInvalidKey, err)
	}
	return pub, nil
}

// PrivateKeyFromBase64 decodes a base64-encoded X25519 private key.
func PrivateKeyFromBase64(encoded string) (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %v", ErrInvalidKey, err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse private key: %v", ErrInvalidKey, err)
	}
	return priv, nil
}

// DeriveSharedKey performs X25519 ECDH and derives a 256-bit key using
// HKDF-SHA256. The salt parameter is optional; pass nil for unsalted derivation.
func DeriveSharedKey(privateKey *ecdh.PrivateKey, peerPublic *ecdh.PublicKey, salt []byte) ([]byte, error) {
	if privateKey == nil || peerPublic == nil {
		return nil, ErrInvalidKey
	}

	shared, err := privateKey.ECDH(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("ecdh exchange: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, shared, salt, hkdfInfo)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// The returned ciphertext is: nonce (12 bytes) || gcm_ciphertext || gcm_tag.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm cipher: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt using AES-256-GCM.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	if len(ciphertext) < NonceSize {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm cipher: %w", err)
	}

	nonce := ciphertext[:NonceSize]
	sealed := ciphertext[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// EncryptForPeer is a convenience function that derives a shared key from a
// key pair and a peer's public key, then encrypts the plaintext. It returns
// base64-encoded ciphertext.
func EncryptForPeer(senderPrivate *ecdh.PrivateKey, recipientPublic *ecdh.PublicKey, plaintext []byte) (string, error) {
	sharedKey, err := DeriveSharedKey(senderPrivate, recipientPublic, nil)
	if err != nil {
		return "", err
	}

	ct, err := Encrypt(sharedKey, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptFromPeer is a convenience function that derives a shared key from a
// key pair and a peer's public key, then decrypts the base64-encoded ciphertext.
func DecryptFromPeer(recipientPrivate *ecdh.PrivateKey, senderPublic *ecdh.PublicKey, encoded string) ([]byte, error) {
	sharedKey, err := DeriveSharedKey(recipientPrivate, senderPublic, nil)
	if err != nil {
		return nil, err
	}

	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %v", ErrInvalidCiphertext, err)
	}

	return Decrypt(sharedKey, ct)
}
