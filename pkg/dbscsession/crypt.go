package dbscsession

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"golang.org/x/crypto/nacl/secretbox"
)

// Decrypts a base64-encoded SecretBox appended to its nonce
func DecryptString(s string) ([]byte, error) {
	decoded, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(decoded) <= 24 {
		return nil, errors.New("Invalid encrypted data: too short")
	}

	var nonce [24]byte
	copy(nonce[:], decoded[0:24])

	box := decoded[24:]

	value, ok := secretbox.Open(nil, box, &nonce, &config.EncryptionSecret)
	if !ok {
		return nil, errors.New("Invalid encrypted data: bad authentication")
	}

	return value, nil
}

// Encrypts a value into base64-encoded SecretBox appended to its nonce
func EncryptToString(data []byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("Could not generate nonce: %w", err)
	}

	// Encrypt the data and append it to the nonce (decryptProxyCookie expects the
	// first 24 bytes to be the nonce)
	proxyCookieBytes := secretbox.Seal(nonce[:], data, &nonce, &config.EncryptionSecret)
	return base64.URLEncoding.EncodeToString(proxyCookieBytes), nil
}

type proxyCookieData struct {
	UpstreamSession string `json:"u"`
	Pubkey          string `json:"k"`
}

func decryptProxyCookie(proxyCookie *http.Cookie) (upstreamCookie *http.Cookie, pubkey *ecdsa.PublicKey, err error) {
	proxyCookieValue, err := DecryptString(proxyCookie.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid proxy cookie: %w", err)
	}

	proxyCookieData := proxyCookieData{}
	err = json.Unmarshal(proxyCookieValue, &proxyCookieData)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid proxy cookie JSON: %w", err)
	}

	if proxyCookieData.UpstreamSession == "" || proxyCookieData.Pubkey == "" {
		return nil, nil, errors.New("Invalid proxy cookie JSON: blank values")
	}

	upstreamCookie, err = http.ParseSetCookie(proxyCookieData.UpstreamSession)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid proxy cookie upstream value: %w", err)
	}

	pubkeyBytes, err := base64.URLEncoding.DecodeString(proxyCookieData.Pubkey)
	if err != nil {
		return nil, nil, errors.New("Invalid proxy pubkey value: bad base64")
	}

	pubkey, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubkeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid proxy cookie upstream value: %w", err)
	}

	return
}
