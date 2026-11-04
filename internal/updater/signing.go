package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// GenerateKeypairHex generates a new Ed25519 release-signing keypair encoded as lowercase hex.
// Public key is 32 bytes (64 hex chars); private key is 64 bytes (128 hex chars).
func GenerateKeypairHex() (publicKeyHex string, privateKeyHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate Ed25519 keypair: %w", err)
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// SignDataHex signs raw payload bytes using either a 32-byte Ed25519 seed (64 hex chars)
// or a 64-byte Ed25519 private key (128 hex chars), returning a 128-char hex signature.
func SignDataHex(privateKeyHex string, data []byte) (string, error) {
	clean := strings.TrimSpace(privateKeyHex)
	rawKey, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("invalid Ed25519 private key hex: %w", err)
	}

	var priv ed25519.PrivateKey
	switch len(rawKey) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(rawKey)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(rawKey)
	default:
		return "", fmt.Errorf("invalid Ed25519 private key length: got %d bytes, expected %d or %d",
			len(rawKey), ed25519.SeedSize, ed25519.PrivateKeySize)
	}

	sig := ed25519.Sign(priv, data)
	return hex.EncodeToString(sig), nil
}

// VerifyDataHex verifies an Ed25519 detached hex signature against a 32-byte public key (64 hex chars).
func VerifyDataHex(publicKeyHex string, data []byte, signatureText string) error {
	cleanPub := strings.TrimSpace(publicKeyHex)
	if cleanPub == "" {
		return errors.New("empty Ed25519 release public key")
	}
	pubBytes, err := hex.DecodeString(cleanPub)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 release public key (expected %d bytes)", ed25519.PublicKeySize)
	}

	fields := strings.Fields(strings.TrimSpace(signatureText))
	if len(fields) == 0 {
		return errors.New("empty Ed25519 signature file")
	}
	sigBytes, err := hex.DecodeString(fields[0])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("malformed Ed25519 signature (expected %d hex-encoded bytes)", ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes) {
		return errors.New("Ed25519 release signature verification failed (untrusted or tampered checksums.txt)")
	}
	return nil
}
