package dbscsession

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/benweissmann/dbsc-proxy/pkg/dbscchallenge"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/secretbox"
)

// testProxyCookieData mirrors the unexported proxyCookieData struct for testing
type testProxyCookieData struct {
	UpstreamSession string `json:"u"`
	Pubkey          string `json:"k"`
}

// setupTestSecrets initializes the global secrets for testing
func setupTestSecrets() {
	testSecret := "test-secret-123456789012345678901234567890"
	h := sha256.New()
	h.Write([]byte(testSecret))
	copy(config.SigningSecret[:], h.Sum(nil))
	copy(config.EncryptionSecret[:], h.Sum(nil))

	// Set global config
	config.Global.CookieName = "session"
	config.Global.RefreshInterval = 15 * time.Minute
}

// generateECDSAKey generates a new ECDSA key pair for testing
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// createValidProxyCookie creates a valid encrypted proxy cookie
func createValidProxyCookie(t *testing.T, upstreamCookie *http.Cookie, pubkey *ecdsa.PublicKey) *http.Cookie {
	t.Helper()

	pubkeyBytes, err := pubkey.Bytes()
	require.NoError(t, err)

	proxyCookieData, err := json.Marshal(&testProxyCookieData{
		UpstreamSession: upstreamCookie.String(),
		Pubkey:          base64.URLEncoding.EncodeToString(pubkeyBytes),
	})
	require.NoError(t, err)

	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes := secretbox.Seal(nonce[:], proxyCookieData, &nonce, &config.EncryptionSecret)

	return &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}
}

// createJWT creates a JWT with the given key and payload
func createJWT(key *ecdsa.PrivateKey, payload dbscchallenge.ChallengeSolutionPayload) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		return "", err
	}

	token, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// Test decryptProxyCookie with valid input
func TestDecryptProxyCookieValid(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-session-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	decryptedUpstream, decryptedPubkey, err := decryptProxyCookie(proxyCookie)
	assert.NoError(t, err)
	assert.NotNil(t, decryptedUpstream)
	assert.NotNil(t, decryptedPubkey)
	assert.Equal(t, "session", decryptedUpstream.Name)
	assert.Equal(t, "test-session-value", decryptedUpstream.Value)
	assert.Equal(t, privKey.PublicKey.X, decryptedPubkey.X)
	assert.Equal(t, privKey.PublicKey.Y, decryptedPubkey.Y)
}

// Test decryptProxyCookie with invalid base64
func TestDecryptProxyCookieInvalidBase64(t *testing.T) {
	setupTestSecrets()

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: "not-valid-base64!!!",
	}

	_, _, err := decryptProxyCookie(proxyCookie)
	assert.Error(t, err)
}

// Test decryptProxyCookie with cookie too short
func TestDecryptProxyCookieTooShort(t *testing.T) {
	setupTestSecrets()

	// Create a value that's too short (less than 24 bytes)
	shortData := []byte("short")
	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(shortData),
	}

	_, _, err := decryptProxyCookie(proxyCookie)
	assert.EqualError(t, err, "Invalid proxy cookie: Invalid encrypted data: too short")
}

// Test decryptProxyCookie with bad authentication
func TestDecryptProxyCookieBadAuth(t *testing.T) {
	setupTestSecrets()

	// Create a nonce and some data, but don't encrypt it properly
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	// Just append random data without proper encryption
	badData := append(nonce[:], []byte("this is not properly encrypted")...)

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(badData),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.EqualError(t, err, "Invalid proxy cookie: Invalid encrypted data: bad authentication")
}

// Test decryptProxyCookie with invalid JSON
func TestDecryptProxyCookieInvalidJSON(t *testing.T) {
	setupTestSecrets()

	// Create properly encrypted data, but with invalid JSON
	invalidJSON := []byte("not valid json{")
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes := secretbox.Seal(nonce[:], invalidJSON, &nonce, &config.EncryptionSecret)

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid proxy cookie JSON")
}

// Test decryptProxyCookie with blank values
func TestDecryptProxyCookieBlankValues(t *testing.T) {
	setupTestSecrets()

	// Test with blank UpstreamSession
	proxyCookieData, err := json.Marshal(&testProxyCookieData{
		UpstreamSession: "",
		Pubkey:          "test",
	})
	require.NoError(t, err)

	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes := secretbox.Seal(nonce[:], proxyCookieData, &nonce, &config.EncryptionSecret)

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.EqualError(t, err, "Invalid proxy cookie JSON: blank values")

	// Test with blank Pubkey
	proxyCookieData, err = json.Marshal(&testProxyCookieData{
		UpstreamSession: "session=test",
		Pubkey:          "",
	})
	require.NoError(t, err)

	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes = secretbox.Seal(nonce[:], proxyCookieData, &nonce, &config.EncryptionSecret)

	proxyCookie = &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.EqualError(t, err, "Invalid proxy cookie JSON: blank values")
}

// Test decryptProxyCookie with invalid upstream cookie
func TestDecryptProxyCookieInvalidUpstreamCookie(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	pubkeyBytes, err := privKey.PublicKey.Bytes()
	require.NoError(t, err)

	// Create data with invalid upstream cookie format
	proxyCookieData, err := json.Marshal(&testProxyCookieData{
		UpstreamSession: "not a valid Set-Cookie header",
		Pubkey:          base64.URLEncoding.EncodeToString(pubkeyBytes),
	})
	require.NoError(t, err)

	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes := secretbox.Seal(nonce[:], proxyCookieData, &nonce, &config.EncryptionSecret)

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid proxy cookie upstream value")
}

// Test decryptProxyCookie with invalid pubkey base64
func TestDecryptProxyCookieInvalidPubkeyBase64(t *testing.T) {
	setupTestSecrets()

	proxyCookieData, err := json.Marshal(&testProxyCookieData{
		UpstreamSession: "session=test",
		Pubkey:          "not-valid-base64!!!",
	})
	require.NoError(t, err)

	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes := secretbox.Seal(nonce[:], proxyCookieData, &nonce, &config.EncryptionSecret)

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.EqualError(t, err, "Invalid proxy pubkey value: bad base64")
}

// Test decryptProxyCookie with invalid pubkey bytes
func TestDecryptProxyCookieInvalidPubkeyBytes(t *testing.T) {
	setupTestSecrets()

	// Create valid base64 but invalid public key bytes
	proxyCookieData, err := json.Marshal(&testProxyCookieData{
		UpstreamSession: "session=test",
		Pubkey:          base64.URLEncoding.EncodeToString([]byte("invalid key bytes")),
	})
	require.NoError(t, err)

	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	require.NoError(t, err)

	proxyCookieBytes := secretbox.Seal(nonce[:], proxyCookieData, &nonce, &config.EncryptionSecret)

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: base64.URLEncoding.EncodeToString(proxyCookieBytes),
	}

	_, _, err = decryptProxyCookie(proxyCookie)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid proxy cookie upstream value")
}

// Test CreateForPubkey
func TestCreateForPubkey(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:     "session",
		Value:    "test-value",
		Path:     "/",
		Domain:   "example.com",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	before := time.Now()
	authorization, err := GenerateRegistrationAuthorization(upstreamCookie)
	require.NoError(t, err)
	session, err := CreateForPubkey(&privKey.PublicKey, authorization)
	require.NoError(t, err)
	after := time.Now()

	assert.NotNil(t, session)
	session.upstreamCookie.Raw = ""
	assert.Equal(t, upstreamCookie, session.upstreamCookie)
	assert.Equal(t, &privKey.PublicKey, session.pubkey)
	assert.True(t, session.sessionCookieTimestamp.After(before) || session.sessionCookieTimestamp.Equal(before))
	assert.True(t, session.sessionCookieTimestamp.Before(after) || session.sessionCookieTimestamp.Equal(after))
}

// Test CreateForPubkey with an invalid authorization string
func TestCreateForPubkeyInvalidAuthorization(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Test with completely invalid base64
	_, err = CreateForPubkey(&privKey.PublicKey, "not-valid-base64!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid authorization string")

	// Test with valid base64 but invalid encrypted data
	_, err = CreateForPubkey(&privKey.PublicKey, base64.URLEncoding.EncodeToString([]byte("too short")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid authorization string")

	// Test with empty string
	_, err = CreateForPubkey(&privKey.PublicKey, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid authorization string")
}

// Test CreateForPubkey with an authorization string encrypted under a different secret
func TestCreateForPubkeyWrongSecret(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	// Generate authorization with current secret
	authorization, err := GenerateRegistrationAuthorization(upstreamCookie)
	require.NoError(t, err)

	// Change the secret
	newSecret := "new-secret-123456789012345678901234567890"
	h := sha256.New()
	h.Write([]byte(newSecret))
	copy(config.SigningSecret[:], h.Sum(nil))
	copy(config.EncryptionSecret[:], h.Sum(nil))

	// Try to decrypt with wrong secret
	_, err = CreateForPubkey(&privKey.PublicKey, authorization)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid authorization string")
}

// Test CreateForPubkey with an unparsable cookie
func TestCreateForPubkeyUnparsableCookie(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Encrypt invalid cookie data
	invalidCookieData := []byte("not a valid Set-Cookie header")
	authorization, err := EncryptToString(invalidCookieData)
	require.NoError(t, err)

	_, err = CreateForPubkey(&privKey.PublicKey, authorization)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid cookie in authorization")
}

// Test LoadFromCookies with valid input
func TestLoadFromCookiesValid(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	// Create a session and convert to cookies
	session := &SecureSession{
		pubkey:                 &privKey.PublicKey,
		upstreamCookie:         upstreamCookie,
		sessionCookieTimestamp: time.Now(),
	}

	proxyCookie, sessionCookie, err := session.ToCookies()
	require.NoError(t, err)

	// Load the session back from cookies
	loadedSession, err := LoadFromCookies(proxyCookie, sessionCookie)
	assert.NoError(t, err)
	assert.NotNil(t, loadedSession)
	assert.Equal(t, "session", loadedSession.upstreamCookie.Name)
	assert.Equal(t, "test-value", loadedSession.upstreamCookie.Value)
	assert.Equal(t, privKey.PublicKey.X, loadedSession.pubkey.X)
	assert.Equal(t, privKey.PublicKey.Y, loadedSession.pubkey.Y)
	assert.InDelta(t, session.sessionCookieTimestamp.Second(), loadedSession.sessionCookieTimestamp.Second(), 5)
}

// Test LoadFromCookies with no separator
func TestLoadFromCookiesNoSeparator(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)
	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "no_separator_here",
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: no separator")
}

// Test LoadFromCookies with wrong prefix
func TestLoadFromCookiesWrongPrefix(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)
	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "wrong_prefix:123:abc",
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: not a dbsc proxy cookie")
}

// Test LoadFromCookies with bad signature format
func TestLoadFromCookiesBadSignatureFormat(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Use standard base64 encoding instead of URL encoding
	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:123:not-valid-url-base64!!!",
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: bad signature format")
}

// Test LoadFromCookies with bad signature
func TestLoadFromCookiesBadSignature(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Create a session cookie with a bad signature
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	badSignature := base64.URLEncoding.EncodeToString([]byte("wrong signature bytes"))
	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + timestamp + ":" + badSignature,
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: bad signature")
}

// Test LoadFromCookies with signature from different secret
func TestLoadFromCookiesSignatureFromDifferentSecret(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	// Create cookies with original secret
	session := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	proxyCookie, sessionCookie, err := session.ToCookies()
	require.NoError(t, err)

	// Change the secret
	differentSecret := "different-secret-key-9876543210-123456"
	h := sha256.New()
	h.Write([]byte(differentSecret))
	copy(config.SigningSecret[:], h.Sum(nil))

	// Try to load - should fail because signature was created with different secret
	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: bad signature")

	// Restore original secret
	setupTestSecrets()
}

// Test LoadFromCookies with bad timestamp format
func TestLoadFromCookiesBadTimestampFormat(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Use non-numeric timestamp
	msg := "not_a_number"
	digest := auth.Sum([]byte(msg+":"+proxyCookie.Value), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + msg + ":" + digestB64,
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: bad timestamp format")
}

// Test LoadFromCookies with expired session
func TestLoadFromCookiesExpiredSession(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Create a timestamp that's too old (beyond refresh interval + slop)
	oldTimestamp := time.Now().Add(-(config.Global.RefreshInterval + config.SessionCookieEnforcementSlop + time.Minute))
	msg := strconv.FormatInt(oldTimestamp.Unix(), 10)
	digest := auth.Sum([]byte(msg+":"+proxyCookie.Value), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + msg + ":" + digestB64,
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Expired session cookie")
}

// Test LoadFromCookies with future timestamp
func TestLoadFromCookiesFutureTimestamp(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Create a timestamp in the future (beyond MAX_AGE from challenge.go)
	futureTimestamp := time.Now().Add(2 * time.Minute)
	msg := strconv.FormatInt(futureTimestamp.Unix(), 10)
	digest := auth.Sum([]byte(msg+":"+proxyCookie.Value), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + msg + ":" + digestB64,
	}

	_, err = LoadFromCookies(proxyCookie, sessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: bad timestamp")
}

// Test LoadFromCookies with invalid proxy cookie
func TestLoadFromCookiesInvalidProxyCookie(t *testing.T) {
	setupTestSecrets()

	// Create an invalid proxy cookie
	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: "invalid-data",
	}

	timestamp := time.Now()
	msg := strconv.FormatInt(timestamp.Unix(), 10)
	digest := auth.Sum([]byte(msg+":"+proxyCookie.Value), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + msg + ":" + digestB64,
	}

	_, err := LoadFromCookies(proxyCookie, sessionCookie)
	assert.Error(t, err)
}

// Test Refresh with valid input
func TestRefreshValid(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Create a valid JWT proof
	challenge := dbscchallenge.NewChallenge()
	payload := dbscchallenge.ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Refresh the session
	before := time.Now()
	session, err := Refresh(proxyCookie, token)
	after := time.Now()

	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "session", session.upstreamCookie.Name)
	assert.Equal(t, "test-value", session.upstreamCookie.Value)
	assert.Equal(t, privKey.PublicKey.X, session.pubkey.X)
	assert.Equal(t, privKey.PublicKey.Y, session.pubkey.Y)
	assert.True(t, session.sessionCookieTimestamp.After(before) || session.sessionCookieTimestamp.Equal(before))
	assert.True(t, session.sessionCookieTimestamp.Before(after) || session.sessionCookieTimestamp.Equal(after))
}

// Test Refresh with invalid proxy cookie
func TestRefreshInvalidProxyCookie(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Invalid proxy cookie
	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: "invalid",
	}

	// Create a valid JWT proof
	challenge := dbscchallenge.NewChallenge()
	payload := dbscchallenge.ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Refresh should fail
	_, err = Refresh(proxyCookie, token)
	assert.Error(t, err)
}

// Test Refresh with invalid JWT proof
func TestRefreshInvalidJWTProof(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Invalid JWT (not actually a JWT)
	invalidToken := "not.a.jwt"

	_, err = Refresh(proxyCookie, invalidToken)
	assert.Error(t, err)
}

// Test Refresh with wrong public key
func TestRefreshWrongPublicKey(t *testing.T) {
	setupTestSecrets()

	privKey1, err := generateECDSAKey()
	require.NoError(t, err)

	privKey2, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	// Create proxy cookie with key1
	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey1.PublicKey)

	// Create JWT proof with key2
	challenge := dbscchallenge.NewChallenge()
	payload := dbscchallenge.ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	token, err := createJWT(privKey2, payload)
	require.NoError(t, err)

	// Refresh should fail because JWT is signed with wrong key
	_, err = Refresh(proxyCookie, token)
	assert.Error(t, err)
}

// Test ToCookies with valid input
func TestToCookiesValid(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	session := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	proxyCookie, sessionCookie, err := session.ToCookies()

	assert.NoError(t, err)
	assert.NotNil(t, proxyCookie)
	assert.NotNil(t, sessionCookie)
	assert.Equal(t, "dbsc_proxy", proxyCookie.Name)
	assert.Equal(t, config.Global.CookieName, sessionCookie.Name)
	assert.True(t, strings.HasPrefix(sessionCookie.Value, "dbsc_proxy:"))
}

// Test ToCookies with invalid curve
func TestToCookiesInvalidCurve(t *testing.T) {
	setupTestSecrets()

	// Create a key with a different curve (P384 instead of P256)
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	session := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	_, _, err = session.ToCookies()

	assert.EqualError(t, err, "Invalid public key curve")
}

// Test ToCookies checks all cookie fields
func TestToCookiesAllFields(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:        "session",
		Value:       "test-value",
		Path:        "/app",
		Domain:      "example.com",
		MaxAge:      7200,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteLaxMode,
		Partitioned: true,
	}

	session := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	proxyCookie, sessionCookie, err := session.ToCookies()

	assert.NoError(t, err)

	// Check proxy cookie fields
	assert.Equal(t, "dbsc_proxy", proxyCookie.Name)
	assert.NotEmpty(t, proxyCookie.Value)
	assert.Equal(t, "/app", proxyCookie.Path)
	assert.Equal(t, "example.com", proxyCookie.Domain)
	assert.Equal(t, 7200, proxyCookie.MaxAge)
	assert.Equal(t, true, proxyCookie.Secure)
	assert.Equal(t, true, proxyCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, proxyCookie.SameSite)
	assert.Equal(t, true, proxyCookie.Partitioned)

	// Check session cookie fields
	assert.Equal(t, "session", sessionCookie.Name)
	assert.True(t, strings.HasPrefix(sessionCookie.Value, "dbsc_proxy:"))
	assert.Equal(t, "/app", sessionCookie.Path)
	assert.Equal(t, "example.com", sessionCookie.Domain)
	// MaxAge should be close to RefreshInterval but may be slightly less due to time passing
	assert.True(t, sessionCookie.MaxAge <= int(config.Global.RefreshInterval.Seconds()))
	assert.True(t, sessionCookie.MaxAge >= int(config.Global.RefreshInterval.Seconds())-5)
	assert.Equal(t, true, sessionCookie.Secure)
	assert.Equal(t, true, sessionCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, sessionCookie.SameSite)
	assert.Equal(t, true, sessionCookie.Partitioned)
}

// Test session cookie expiration enforcement with slop
func TestSessionCookieEnforcementSlop(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey.PublicKey)

	// Create a timestamp that's exactly at the refresh interval (should still be valid due to slop)
	almostExpiredTimestamp := time.Now().Add(-config.Global.RefreshInterval)
	msg := strconv.FormatInt(almostExpiredTimestamp.Unix(), 10)
	digest := auth.Sum([]byte(msg+":"+proxyCookie.Value), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + msg + ":" + digestB64,
	}

	// Should still load successfully due to slop
	loadedSession, err := LoadFromCookies(proxyCookie, sessionCookie)
	assert.NoError(t, err)
	assert.NotNil(t, loadedSession)
}

// Test tampered session cookie
func TestTamperedSessionCookie(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	// Create valid cookies
	session := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	proxyCookie, sessionCookie, err := session.ToCookies()
	require.NoError(t, err)

	// Tamper with the session cookie value by changing the timestamp
	parts := strings.Split(sessionCookie.Value, ":")
	require.Len(t, parts, 3)

	// Change the timestamp
	newTimestamp := strconv.FormatInt(time.Now().Add(1*time.Hour).Unix(), 10)
	tamperedValue := parts[0] + ":" + newTimestamp + ":" + parts[2]

	tamperedSessionCookie := &http.Cookie{
		Name:  sessionCookie.Name,
		Value: tamperedValue,
	}

	// Should fail verification
	_, err = LoadFromCookies(proxyCookie, tamperedSessionCookie)
	assert.EqualError(t, err, "Invalid session cookie: bad signature")
}

// Test cookies signed with wrong public key
func TestWrongPublicKeySignature(t *testing.T) {
	setupTestSecrets()

	privKey1, err := generateECDSAKey()
	require.NoError(t, err)

	privKey2, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	// Create proxy cookie with key1
	proxyCookie := createValidProxyCookie(t, upstreamCookie, &privKey1.PublicKey)

	// Create session cookie for key2 (but use the proxy cookie from key1)
	session2 := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey2.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	_, sessionCookie2, err := session2.ToCookies()
	require.NoError(t, err)

	// Modify the session cookie to reference the proxyCookie from key1
	parts := strings.Split(sessionCookie2.Value, ":")
	require.Len(t, parts, 3)

	timestamp := parts[1]
	msg := timestamp + ":" + proxyCookie.Value
	digest := auth.Sum([]byte(msg), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	mixedSessionCookie := &http.Cookie{
		Name:  "session",
		Value: "dbsc_proxy:" + timestamp + ":" + digestB64,
	}

	// Load should succeed because signature is valid, but the pubkey won't match
	loadedSession, err := LoadFromCookies(proxyCookie, mixedSessionCookie)
	assert.NoError(t, err)
	assert.NotNil(t, loadedSession)
	// The loaded session will have key1's pubkey (from proxy cookie)
	assert.Equal(t, privKey1.PublicKey.X, loadedSession.pubkey.X)
	assert.Equal(t, privKey1.PublicKey.Y, loadedSession.pubkey.Y)
}

// Test empty inputs
func TestEmptyInputs(t *testing.T) {
	setupTestSecrets()

	proxyCookie := &http.Cookie{
		Name:  "dbsc_proxy",
		Value: "",
	}

	sessionCookie := &http.Cookie{
		Name:  "session",
		Value: "",
	}

	_, err := LoadFromCookies(proxyCookie, sessionCookie)
	assert.Error(t, err)
}

// Test round-trip (ToCookies then LoadFromCookies)
func TestRoundTrip(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	upstreamCookie := &http.Cookie{
		Name:        "session",
		Value:       "original-value",
		Path:        "/test",
		Domain:      "test.example.com",
		MaxAge:      3600,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteStrictMode,
		Partitioned: false,
	}

	// Create session
	originalSession := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	// Convert to cookies
	proxyCookie, sessionCookie, err := originalSession.ToCookies()
	require.NoError(t, err)

	// Load back from cookies
	loadedSession, err := LoadFromCookies(proxyCookie, sessionCookie)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, "session", loadedSession.upstreamCookie.Name)
	assert.Equal(t, "original-value", loadedSession.upstreamCookie.Value)
	assert.Equal(t, "/test", loadedSession.upstreamCookie.Path)
	assert.Equal(t, "test.example.com", loadedSession.upstreamCookie.Domain)
	assert.Equal(t, 3600, loadedSession.upstreamCookie.MaxAge)
	assert.Equal(t, true, loadedSession.upstreamCookie.Secure)
	assert.Equal(t, true, loadedSession.upstreamCookie.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, loadedSession.upstreamCookie.SameSite)
	assert.Equal(t, false, loadedSession.upstreamCookie.Partitioned)
	assert.Equal(t, privKey.PublicKey.X, loadedSession.pubkey.X)
	assert.Equal(t, privKey.PublicKey.Y, loadedSession.pubkey.Y)

	// Test CookieForUpstream
	assert.Equal(t, "session", loadedSession.CookieForUpstream().Name)
	assert.Equal(t, "original-value", loadedSession.CookieForUpstream().Value)
}

// Test WithNewUpstreamCookie preserves pubkey and timestamp
func TestWithNewUpstreamCookie(t *testing.T) {
	setupTestSecrets()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	originalCookie := &http.Cookie{
		Name:        "session",
		Value:       "original-value",
		Path:        "/original",
		Domain:      "original.example.com",
		MaxAge:      3600,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteStrictMode,
		Partitioned: true,
	}

	// Create original session
	originalSession := SecureSession{
		upstreamCookie:         originalCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	// Create a new cookie with different values
	newCookie := &http.Cookie{
		Name:        "newsession",
		Value:       "new-value",
		Path:        "/new",
		Domain:      "new.example.com",
		MaxAge:      7200,
		Secure:      false,
		HttpOnly:    false,
		SameSite:    http.SameSiteLaxMode,
		Partitioned: false,
	}

	// Create new session with updated cookie
	newSession := originalSession.WithNewUpstreamCookie(newCookie)

	// Verify the upstream cookie was updated
	assert.Equal(t, "newsession", newSession.upstreamCookie.Name)
	assert.Equal(t, "new-value", newSession.upstreamCookie.Value)
	assert.Equal(t, "/new", newSession.upstreamCookie.Path)
	assert.Equal(t, "new.example.com", newSession.upstreamCookie.Domain)
	assert.Equal(t, 7200, newSession.upstreamCookie.MaxAge)
	assert.Equal(t, false, newSession.upstreamCookie.Secure)
	assert.Equal(t, false, newSession.upstreamCookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, newSession.upstreamCookie.SameSite)
	assert.Equal(t, false, newSession.upstreamCookie.Partitioned)

	// Verify pubkey and timestamp are preserved
	assert.Equal(t, originalSession.pubkey.X, newSession.pubkey.X)
	assert.Equal(t, originalSession.pubkey.Y, newSession.pubkey.Y)
	assert.Equal(t, originalSession.sessionCookieTimestamp, newSession.sessionCookieTimestamp)

	// Verify the original session was not modified
	assert.Equal(t, "session", originalSession.upstreamCookie.Name)
	assert.Equal(t, "original-value", originalSession.upstreamCookie.Value)
}
