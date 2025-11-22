package dbscchallenge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/auth"
)

// setupTestSecret initializes the global secret for testing
func setupTestSecret() {
	// Use a fixed secret for testing and hash it like config.ParseEnv does
	testSecret := "test-secret-123456789012345678901234567890"
	h := sha256.New()
	h.Write([]byte(testSecret))
	copy(config.SigningSecret[:], h.Sum(nil))
}

// generateECDSAKey generates a new ECDSA key pair for testing
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// generateRSAKey generates a new RSA key pair for testing
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// createJWT creates a JWT with the given key and payload
func createJWT(key interface{}, payload ChallengeSolutionPayload) (string, error) {
	var alg jose.SignatureAlgorithm
	switch key.(type) {
	case *ecdsa.PrivateKey:
		alg = jose.ES256
	case *rsa.PrivateKey:
		alg = jose.RS256
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, nil)
	if err != nil {
		return "", err
	}

	token, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// createJWS creates a JWS with the key included in the header
func createJWS(key *ecdsa.PrivateKey, payload ChallengeSolutionPayload) (string, error) {
	jwk := jose.JSONWebKey{Key: key, Algorithm: string(jose.ES256)}

	opts := &jose.SignerOptions{}
	opts.WithHeader("jwk", jwk.Public())

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", err
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return "", err
	}

	return jws.CompactSerialize()
}

func TestNewChallenge(t *testing.T) {
	setupTestSecret()

	before := time.Now()
	challenge := NewChallenge()
	after := time.Now()

	assert.NotNil(t, challenge)
	assert.True(t, challenge.timestamp.After(before) || challenge.timestamp.Equal(before))
	assert.True(t, challenge.timestamp.Before(after) || challenge.timestamp.Equal(after))
}

func TestVerifyValid(t *testing.T) {
	setupTestSecret()

	challenge := NewChallenge()
	signed := challenge.Sign()

	verified, err := verify(signed, MAX_AGE)
	assert.NoError(t, err)
	assert.NotNil(t, verified)
	assert.Equal(t, challenge.timestamp.Unix(), verified.timestamp.Unix())
}

func TestVerifyInvalidFormat(t *testing.T) {
	setupTestSecret()

	// Only one part
	_, err := verify("onlyonepart", MAX_AGE)
	assert.EqualError(t, err, "Invalid challenge format: no separator")
}

func TestVerifyInvalidSignature(t *testing.T) {
	setupTestSecret()

	challenge := NewChallenge()
	signed := challenge.Sign()

	// Tamper with the signature
	parts := strings.Split(signed, ":")
	tampered := parts[0] + ":d3JvbmdzaWduYXR1cmU="

	_, err := verify(tampered, MAX_AGE)
	assert.EqualError(t, err, "Invalid challenge: bad signature")
}

func TestVerifySignatureFromDifferentSecret(t *testing.T) {
	setupTestSecret()

	challenge := NewChallenge()
	signed := challenge.Sign()

	// Change the global secret to a different one
	differentSecret := "different-secret-key-9876543210"
	h := sha256.New()
	h.Write([]byte(differentSecret))
	copy(config.SigningSecret[:], h.Sum(nil))

	// The signature should now be invalid because it was signed with the original secret
	_, err := verify(signed, MAX_AGE)
	assert.EqualError(t, err, "Invalid challenge: bad signature")

	// Restore the original secret for other tests
	setupTestSecret()
}

func TestVerifyInvalidSignatureFormat(t *testing.T) {
	setupTestSecret()

	msg := strconv.FormatInt(time.Now().Unix(), 10)
	digestB64 := "~bad~"
	_, err := verify(msg+":"+digestB64, MAX_AGE)
	assert.EqualError(t, err, "Invalid challenge: bad signature format")
}

func TestVerifyInvalidTimestamp(t *testing.T) {
	setupTestSecret()

	// Non-numeric timestamp
	msg := "123notanumber"
	digest := auth.Sum([]byte(msg), &config.SigningSecret)
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])

	_, err := verify(msg+":"+digestB64, MAX_AGE)
	assert.EqualError(t, err, "Invalid challenge: bad timestamp format")
}

func TestVerifyExpiredChallenge(t *testing.T) {
	setupTestSecret()

	// Create a challenge from 2 minutes ago
	oldChallenge := &DBSCChallenge{
		timestamp: time.Now().Add(-2 * time.Minute),
	}
	signed := oldChallenge.Sign()

	_, err := verify(signed, MAX_AGE)
	assert.EqualError(t, err, "Expired challenge")
}

func TestVerifyFutureChallenge(t *testing.T) {
	setupTestSecret()

	// Create a challenge from the future (2 minutes ahead)
	futureChallenge := &DBSCChallenge{
		timestamp: time.Now().Add(2 * time.Minute),
	}
	signed := futureChallenge.Sign()

	_, err := verify(signed, MAX_AGE)
	assert.EqualError(t, err, "Invalid challenge: bad timestamp")
}

func TestVerifyFromJWTValid(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Create JWT
	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Verify
	err = VerifyFromJWT(token, &privKey.PublicKey)
	assert.NoError(t, err)
}

func TestVerifyFromJWTMissingJti(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create JWT
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privKey}, nil)
	require.NoError(t, err)

	cl := jwt.Claims{}
	token, err := jwt.Signed(signer).Claims(cl).Serialize()
	require.NoError(t, err)

	// Verify
	err = VerifyFromJWT(token, &privKey.PublicKey)
	assert.EqualError(t, err, "Invalid challenge solution: missing jti")
}

func TestVerifyFromJWTBlankJti(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create payload with empty jti
	payload := ChallengeSolutionPayload{
		Jti: "",
	}

	// Create JWT
	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Verify
	err = VerifyFromJWT(token, &privKey.PublicKey)
	assert.EqualError(t, err, "Invalid challenge solution: missing jti")
}

func TestVerifyFromJWTInvalidChallenge(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create payload with invalid challenge
	payload := ChallengeSolutionPayload{
		Jti: fmt.Sprintf("%d:d3JvbmdzaWduYXR1cmU=", time.Now().Unix()),
	}

	// Create JWT
	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Verify
	err = VerifyFromJWT(token, &privKey.PublicKey)
	assert.EqualError(t, err, "Invalid challenge: bad signature")
}

func TestVerifyFromJWTExpiredChallenge(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create an expired challenge
	oldChallenge := &DBSCChallenge{
		timestamp: time.Now().Add(-2 * time.Minute),
	}

	payload := ChallengeSolutionPayload{
		Jti: oldChallenge.Sign(),
	}

	// Create JWT
	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Verify
	err = VerifyFromJWT(token, &privKey.PublicKey)
	assert.EqualError(t, err, "Expired challenge")
}

func TestVerifyFromJWTWrongKey(t *testing.T) {
	setupTestSecret()

	// Generate two different keys
	privKey1, err := generateECDSAKey()
	require.NoError(t, err)

	privKey2, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Create JWT with key1
	token, err := createJWT(privKey1, payload)
	require.NoError(t, err)

	// Try to verify with key2
	err = VerifyFromJWT(token, &privKey2.PublicKey)
	assert.ErrorContains(t, err, "go-jose/go-jose")
}

func TestVerifyFromJWTTamperedPayload(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Create JWT
	token, err := createJWT(privKey, payload)
	require.NoError(t, err)

	// Tamper with the payload
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	// Decode the payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	// Modify the payload
	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	require.NoError(t, err)

	payloadMap["jti"] = "tampered:value"

	// Re-encode
	tamperedPayloadBytes, err := json.Marshal(payloadMap)
	require.NoError(t, err)

	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayloadBytes)
	tamperedToken := strings.Join(parts, ".")

	// Verify should fail
	err = VerifyFromJWT(tamperedToken, &privKey.PublicKey)
	assert.ErrorContains(t, err, "go-jose/go-jose")
}

func TestVerifyFromJWTNoneAlgorithm(t *testing.T) {
	setupTestSecret()

	// Generate key for later verification attempt
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Manually create a JWT with "none" algorithm
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// JWT with none algorithm has empty signature
	noneToken := headerB64 + "." + payloadB64 + "."

	// Verify should fail
	err = VerifyFromJWT(noneToken, &privKey.PublicKey)
	assert.EqualError(t, err, "unexpected signature algorithm \"none\"; expected [\"ES256\"]")
}

func TestVerifyFromJWTRS256Algorithm(t *testing.T) {
	setupTestSecret()

	// Generate RSA key
	rsaPrivKey, err := generateRSAKey()
	require.NoError(t, err)

	// Generate ECDSA key for verification (wrong type)
	ecdsaPrivKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Create JWT with RS256
	token, err := createJWT(rsaPrivKey, payload)
	require.NoError(t, err)

	// Try to verify with ECDSA key - should fail because algorithm doesn't match
	err = VerifyFromJWT(token, &ecdsaPrivKey.PublicKey)
	assert.EqualError(t, err, "unexpected signature algorithm \"RS256\"; expected [\"ES256\"]")
}

func TestVerifyFromJWTInvalidToken(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Try to verify completely invalid token
	err = VerifyFromJWT("not.a.jwt", &privKey.PublicKey)
	assert.EqualError(t, err, "illegal base64 data at input byte 0")

	// Try with malformed JWT
	err = VerifyFromJWT("invalid", &privKey.PublicKey)
	assert.EqualError(t, err, "go-jose/go-jose: compact JWS format must have three parts")
}

func TestVerifyFromUserProvidedKeyValid(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti:           challenge.Sign(),
		Authorization: "something",
	}

	// Create JWS with key in header
	jws, err := createJWS(privKey, payload)
	require.NoError(t, err)

	// Verify
	returnedKey, authorization, err := VerifyFromUserProvidedKey(jws)
	assert.NoError(t, err)
	assert.NotNil(t, returnedKey)
	assert.Equal(t, elliptic.P256(), returnedKey.Curve)
	assert.Equal(t, privKey.PublicKey.X, returnedKey.X)
	assert.Equal(t, privKey.PublicKey.Y, returnedKey.Y)
	assert.Equal(t, "something", authorization)
}

func TestVerifyFromUserProvidedKeyValidNoAuthorization(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Create JWS with key in header
	jws, err := createJWS(privKey, payload)
	require.NoError(t, err)

	// Verify
	returnedKey, authorization, err := VerifyFromUserProvidedKey(jws)
	assert.NoError(t, err)
	assert.NotNil(t, returnedKey)
	assert.Equal(t, "", authorization)
}

func TestVerifyFromUserProvidedKeyInvalidJWS(t *testing.T) {
	setupTestSecret()

	// Try with invalid JWS
	_, _, err := VerifyFromUserProvidedKey("badjws")
	assert.EqualError(t, err, "go-jose/go-jose: compact JWS format must have three parts")
}

func TestVerifyFromUserProvidedKeyMissingJti(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create payload with empty jti
	payload := ChallengeSolutionPayload{
		Jti: "",
	}

	// Create JWS
	jws, err := createJWS(privKey, payload)
	require.NoError(t, err)

	// Verify
	_, _, err = VerifyFromUserProvidedKey(jws)
	assert.EqualError(t, err, "Invalid challenge solution: missing jti")
}

func TestVerifyFromUserProvidedKeyBadSignature(t *testing.T) {
	setupTestSecret()
	fmt.Println("a134321")

	// Generate two different keys
	privKey1, err := generateECDSAKey()
	require.NoError(t, err)

	privKey2, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	// Create JWS signed with key1
	jws, err := createJWS(privKey1, payload)
	require.NoError(t, err)

	// Parse the JWS to manipulate it
	parts := strings.Split(jws, ".")
	require.Len(t, parts, 3)

	// Decode the header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]interface{}
	err = json.Unmarshal(headerBytes, &header)
	require.NoError(t, err)

	// Replace the JWK in the header with key2's public key
	jwk2 := jose.JSONWebKey{Key: &privKey2.PublicKey}
	jwk2Map := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(jwk2.Key.(*ecdsa.PublicKey).X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(jwk2.Key.(*ecdsa.PublicKey).Y.Bytes()),
	}
	header["jwk"] = jwk2Map

	// Re-encode the header
	tamperedHeaderBytes, err := json.Marshal(header)
	require.NoError(t, err)
	parts[0] = base64.RawURLEncoding.EncodeToString(tamperedHeaderBytes)

	tamperedJWS := strings.Join(parts, ".")

	// Verify should fail because the signature was created with key1 but header claims key2
	_, _, err = VerifyFromUserProvidedKey(tamperedJWS)
	assert.ErrorContains(t, err, "go-jose/go-jose")
}

func TestVerifyFromUserProvidedKeyInvalidChallenge(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create payload with invalid challenge
	payload := ChallengeSolutionPayload{
		Jti: fmt.Sprintf("%d:d3JvbmdzaWduYXR1cmU=", time.Now().Unix()),
	}

	// Create JWS
	jws, err := createJWS(privKey, payload)
	require.NoError(t, err)

	// Verify
	_, _, err = VerifyFromUserProvidedKey(jws)
	assert.EqualError(t, err, "Invalid challenge: bad signature")
}

func TestVerifyFromUserProvidedKeyExpiredChallenge(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create an expired challenge
	oldChallenge := &DBSCChallenge{
		timestamp: time.Now().Add(-2 * time.Minute),
	}

	payload := ChallengeSolutionPayload{
		Jti: oldChallenge.Sign(),
	}

	// Create JWS
	jws, err := createJWS(privKey, payload)
	require.NoError(t, err)

	// Verify
	_, _, err = VerifyFromUserProvidedKey(jws)
	assert.EqualError(t, err, "Expired challenge")
}

func TestVerifyFromUserProvidedKeyMultipleSignatures(t *testing.T) {
	setupTestSecret()

	// Generate keys
	privKey1, err := generateECDSAKey()
	require.NoError(t, err)

	privKey2, err := generateECDSAKey()
	require.NoError(t, err)

	// Create a valid challenge
	challenge := NewChallenge()
	payload := ChallengeSolutionPayload{
		Jti: challenge.Sign(),
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	// Create JWS with multiple signatures using NewMultiSigner
	jwk1 := jose.JSONWebKey{Key: privKey1, Algorithm: string(jose.ES256)}

	// Create SignerOptions that will include jwk headers for both
	opts := &jose.SignerOptions{}
	opts.WithHeader("jwk", jwk1.Public())
	opts.EmbedJWK = true

	// Use NewMultiSigner to create a JWS with multiple signatures
	multiSigner, err := jose.NewMultiSigner([]jose.SigningKey{
		{Algorithm: jose.ES256, Key: privKey1},
		{Algorithm: jose.ES256, Key: privKey2},
	}, opts)
	require.NoError(t, err)

	// Sign the payload
	jws, err := multiSigner.Sign(payloadBytes)
	require.NoError(t, err)

	// Serialize as full JWS (not compact)
	multiSigJWS := jws.FullSerialize()

	// Verify - should fail due to multiple signatures
	_, _, err = VerifyFromUserProvidedKey(multiSigJWS)
	assert.EqualError(t, err, "JWS contains multiple signatures")
}

func TestVerifyFromUserProvidedKeyInvalidJSON(t *testing.T) {
	setupTestSecret()

	// Generate key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Create JWS with invalid JSON payload
	jwk := jose.JSONWebKey{Key: privKey, Algorithm: string(jose.ES256)}
	opts := &jose.SignerOptions{}
	opts.WithHeader("jwk", jwk.Public())

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: privKey}, opts)
	require.NoError(t, err)

	// Sign invalid JSON
	jws, err := signer.Sign([]byte("{invalid json"))
	require.NoError(t, err)

	jwsStr, err := jws.CompactSerialize()
	require.NoError(t, err)

	// Verify - should fail due to invalid JSON
	_, _, err = VerifyFromUserProvidedKey(jwsStr)
	assert.Error(t, err)
}
