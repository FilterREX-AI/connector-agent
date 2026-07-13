// ForgeAI Connector Host — Host Keypair & Asymmetric Credential Crypto
//
// Provides NaCl box (X25519 + XSalsa20-Poly1305) encryption for
// per-target credential delivery. The host generates a keypair on
// first enrollment. The backend encrypts secrets to the host's public
// key. Only the host can decrypt.
//
// Key management:
//   - Keypair generated once at enrollment, persisted in encrypted store
//   - Public key registered with backend during enrollment
//   - Private key never leaves the host
//   - Explicit rotation requires re-enrollment or deliberate action

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"path/filepath"
	"os"

	"golang.org/x/crypto/nacl/box"
)

const (
	hostKeyPairFile = "host_keypair.enc"
	// NaCl box uses 32-byte keys
	naclKeySize   = 32
	naclNonceSize = 24
)

// HostKeyPair holds the host's NaCl box keypair.
type HostKeyPair struct {
	PublicKey  [naclKeySize]byte `json:"public_key"`
	PrivateKey [naclKeySize]byte `json:"private_key"`
}

// GenerateHostKeyPair creates a new NaCl box keypair.
func GenerateHostKeyPair() (*HostKeyPair, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &HostKeyPair{
		PublicKey:  *pub,
		PrivateKey: *priv,
	}, nil
}

// PublicKeyBase64 returns the base64-encoded public key for registration.
func (kp *HostKeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey[:])
}

// ── Keypair Persistence (via encrypted store) ──

// SaveKeyPair encrypts and persists the host keypair.
func (s *Store) SaveKeyPair(kp *HostKeyPair) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Serialize: 32 bytes public + 32 bytes private
	raw := make([]byte, naclKeySize*2)
	copy(raw[:naclKeySize], kp.PublicKey[:])
	copy(raw[naclKeySize:], kp.PrivateKey[:])

	ciphertext, err := s.encrypt(raw)
	if err != nil {
		return fmt.Errorf("encrypt keypair: %w", err)
	}

	path := filepath.Join(s.configDir, hostKeyPairFile)
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write keypair: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename keypair: %w", err)
	}

	return nil
}

// LoadKeyPair loads the host keypair from the encrypted store.
// Returns nil (not error) if no keypair exists.
func (s *Store) LoadKeyPair() (*HostKeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.configDir, hostKeyPairFile)
	ciphertext, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read keypair: %w", err)
	}

	raw, err := s.decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt keypair: %w", err)
	}

	if len(raw) != naclKeySize*2 {
		return nil, fmt.Errorf("invalid keypair data length: %d", len(raw))
	}

	kp := &HostKeyPair{}
	copy(kp.PublicKey[:], raw[:naclKeySize])
	copy(kp.PrivateKey[:], raw[naclKeySize:])
	return kp, nil
}

// ── Credential Decryption ──

// DecryptCredentialPayload decrypts a NaCl box-encrypted credential blob.
// The blob format is: 32-byte sender public key + 24-byte nonce + ciphertext
func DecryptCredentialPayload(encryptedBlob string, hostKeyPair *HostKeyPair) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedBlob)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted blob: %w", err)
	}

	minSize := naclKeySize + naclNonceSize + box.Overhead
	if len(data) < minSize {
		return nil, fmt.Errorf("encrypted blob too short: %d bytes (minimum %d)", len(data), minSize)
	}

	var senderPub [naclKeySize]byte
	copy(senderPub[:], data[:naclKeySize])

	var nonce [naclNonceSize]byte
	copy(nonce[:], data[naclKeySize:naclKeySize+naclNonceSize])

	ciphertext := data[naclKeySize+naclNonceSize:]

	plaintext, ok := box.Open(nil, ciphertext, &nonce, &senderPub, &hostKeyPair.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed: invalid ciphertext or wrong key")
	}

	return plaintext, nil
}

// ── Server-side encryption helper (used in edge functions, mirrored here for tests) ──

// EncryptForHost encrypts data for a host using its public key.
// Uses an ephemeral sender keypair for each encryption.
// Returns base64-encoded blob: senderPub(32) + nonce(24) + ciphertext
func EncryptForHost(plaintext []byte, hostPublicKey [naclKeySize]byte) (string, error) {
	// Generate ephemeral sender keypair
	senderPub, senderPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}

	var nonce [naclNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	encrypted := box.Seal(nil, plaintext, &nonce, &hostPublicKey, senderPriv)

	// Build blob: senderPub + nonce + ciphertext
	blob := make([]byte, 0, naclKeySize+naclNonceSize+len(encrypted))
	blob = append(blob, senderPub[:]...)
	blob = append(blob, nonce[:]...)
	blob = append(blob, encrypted...)

	return base64.StdEncoding.EncodeToString(blob), nil
}
