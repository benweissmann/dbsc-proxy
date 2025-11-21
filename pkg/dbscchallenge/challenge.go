package dbscchallenge

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/benweissmann/dbsc-proxy/pkg/dbsctime"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/nacl/auth"
)

const MAX_AGE = time.Minute

type DBSCChallenge struct {
	timestamp time.Time
}

func NewChallenge() *DBSCChallenge {
	return &DBSCChallenge{
		timestamp: dbsctime.Now(),
	}
}

// Returns the challenge as a signed value. The signed value contains
// only Base64-URL characters and colon, and is safe to use without quoting.
func (c *DBSCChallenge) Sign() string {
	msg := strconv.FormatInt(c.timestamp.Unix(), 10)
	digest := auth.Sum([]byte(msg), &config.SigningSecret)

	// Encode digest as base64 to avoid issues with binary data in JSON
	digestB64 := base64.URLEncoding.EncodeToString(digest[:])
	return msg + ":" + digestB64
}

// Unmarshals the challenge and verifies the signature and freshness
func verify(data string, maxAge time.Duration) (*DBSCChallenge, error) {
	split := strings.SplitN(data, ":", 2)
	if len(split) != 2 {
		return nil, fmt.Errorf("Invalid challenge format: no separator")
	}

	msg := split[0]
	digestB64 := split[1]

	// Decode base64 digest
	digestBytes, err := base64.URLEncoding.DecodeString(digestB64)
	if err != nil {
		return nil, fmt.Errorf("Invalid challenge: bad signature format")
	}

	ok := auth.Verify(digestBytes, []byte(msg), &config.SigningSecret)
	if !ok {
		return nil, fmt.Errorf("Invalid challenge: bad signature")
	}

	tsSeconds, err := strconv.ParseInt(msg, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Invalid challenge: bad timestamp format")
	}

	timestamp := time.Unix(tsSeconds, 0)
	tsAge := dbsctime.Since(timestamp)

	if tsAge.Seconds() > maxAge.Seconds() {
		return nil, fmt.Errorf("Expired challenge")
	}

	if -tsAge.Seconds() > maxAge.Seconds() {
		// Challenge in the future -- this should never happen; we should never
		// generate a future-dated challenge
		return nil, fmt.Errorf("Invalid challenge: bad timestamp")
	}

	return &DBSCChallenge{timestamp: timestamp}, nil
}

type ChallengeSolutionPayload struct {
	Jti           string `json:"jti"`
	Authorization string `json:"authorization,omitempty"`
}

// Verifies a JWT containing a "jti" claim, and then verifies that the "jti"
// claim is a valid, recent challenge. Returns nil on success or an error on
// failure.
func VerifyFromJWT(jwtStr string, pubkey *ecdsa.PublicKey) error {
	tok, err := jwt.ParseSigned(jwtStr, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return err
	}

	parsed := new(ChallengeSolutionPayload)
	if err := tok.Claims(pubkey, &parsed); err != nil {
		return err
	}

	if parsed.Jti == "" {
		return errors.New("Invalid challenge solution: missing jti")
	}

	_, err = verify(parsed.Jti, MAX_AGE)
	if err != nil {
		return err
	}

	return nil
}

// Verifies a challenge from a JWS with a key provided in the header. This
// should *only* be used when registering a session to bind the session to
// the given public key; refresh operations must use the bound key and not
// a user-provided key.
//
// If the JWS is valid, signed with an ECDSA key, and contains a valid, recent
// challenge, then we return the user-provided public key, and the
// "authorization". field of the JWS. Otherwise, we return an error.
func VerifyFromUserProvidedKey(jws string) (*ecdsa.PublicKey, string, error) {
	object, err := jose.ParseSigned(jws, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, "", err
	}

	if len(object.Signatures) != 1 {
		return nil, "", errors.New("JWS contains multiple signatures")
	}

	jwk := object.Signatures[0].Protected.JSONWebKey
	if jwk == nil {
		return nil, "", errors.New("No JWS key")
	}

	ecdsaKey, typeOK := jwk.Key.(*ecdsa.PublicKey)
	if !typeOK {
		// Should never happen -- we specify only ES256 keys above
		return nil, "", errors.New("Invalid JWS key")
	}

	payload, err := object.Verify(ecdsaKey)
	if err != nil {
		return nil, "", err
	}

	parsed := new(ChallengeSolutionPayload)
	err = json.Unmarshal([]byte(payload), &parsed)
	if err != nil {
		return nil, "", err
	}

	if parsed.Jti == "" {
		return nil, "", errors.New("Invalid challenge solution: missing jti")
	}

	_, err = verify(parsed.Jti, MAX_AGE)
	if err != nil {
		return nil, "", err
	}

	return ecdsaKey, parsed.Authorization, nil
}
