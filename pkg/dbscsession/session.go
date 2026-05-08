package dbscsession

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/benweissmann/dbsc-proxy/pkg/dbscchallenge"
	"github.com/benweissmann/dbsc-proxy/pkg/dbsctime"
	"golang.org/x/crypto/nacl/auth"
)

type SecureSession struct {
	upstreamCookie         *http.Cookie
	pubkey                 *ecdsa.PublicKey
	sessionCookieTimestamp time.Time
}

type registrationAuthorizationData struct {
	UpstreamCookie string `json:"upstream_session"`
	Challenge      string `json:"challenge"`
}

func CreateForPubkey(verifiedUserProvidedKey *dbscchallenge.VerifiedUserProvidedKey, upstreamCookieGivenValue string) (*SecureSession, error) {
	registrationAuthorizationBytes, err := DecryptString(&config.RegistrationAuthorizationEncryptionSecret, verifiedUserProvidedKey.Authorization)
	if err != nil {
		return nil, fmt.Errorf("Invalid authorization string: %w", err)
	}

	registrationAuthorizationData := registrationAuthorizationData{}
	err = json.Unmarshal(registrationAuthorizationBytes, &registrationAuthorizationData)
	if err != nil {
		return nil, fmt.Errorf("Invalid authorization data: %w", err)
	}

	if registrationAuthorizationData.Challenge != verifiedUserProvidedKey.VerifiedChallenge {
		return nil, fmt.Errorf("Challenge in authorization did not match the provided challenge in registration request")
	}

	upstreamCookie, err := http.ParseSetCookie(string(registrationAuthorizationData.UpstreamCookie))
	if err != nil {
		return nil, fmt.Errorf("Invalid cookie in authorization: %w", err)
	}

	if upstreamCookie.Value != upstreamCookieGivenValue {
		return nil, fmt.Errorf("Upstream cookie value in authorization did not match client's provided upstream cookie value")
	}

	return &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 verifiedUserProvidedKey.UserProvidedKey,
		sessionCookieTimestamp: dbsctime.Now(),
	}, nil
}

func LoadFromCookies(proxyCookie *http.Cookie, sessionCookie *http.Cookie) (*SecureSession, error) {
	// Validate session cookie
	split := strings.SplitN(sessionCookie.Value, ":", 3)
	if len(split) != 3 {
		return nil, errors.New("Invalid session cookie: no separator")
	}

	if split[0] != config.SessionCookieFirstPart {
		return nil, errors.New("Invalid session cookie: not a dbsc proxy cookie")
	}

	msg := split[1]
	digestB64 := split[2]

	digestBytes, err := base64.URLEncoding.DecodeString(digestB64)
	if err != nil {
		return nil, errors.New("Invalid session cookie: bad signature format")
	}

	ok := auth.Verify(digestBytes, []byte(msg+":"+proxyCookie.Value), &config.SessionCookieSigningSecret)
	if !ok {
		return nil, errors.New("Invalid session cookie: bad signature")
	}

	tsSeconds, err := strconv.ParseInt(msg, 10, 64)
	if err != nil {
		return nil, errors.New("Invalid session cookie: bad timestamp format")
	}

	timestamp := time.Unix(tsSeconds, 0)
	tsAge := dbsctime.Since(timestamp)

	// Add 30 seconds to enforcement of refresh interval so a about-to-expire
	// cookie can still be sent, even if it takes 30 seconds to receive
	if tsAge.Seconds() > (config.Global.RefreshInterval.Seconds() + config.SessionCookieEnforcementSlop.Seconds()) {
		return nil, errors.New("Expired session cookie")
	}

	if -tsAge.Seconds() > dbscchallenge.MAX_AGE.Seconds() {
		// Challenge in the future -- this should never happen; we should never
		// generate a future-dated session cookie
		return nil, errors.New("Invalid session cookie: bad timestamp")
	}

	// load proxy cookie
	upstreamCookie, pubkey, err := decryptProxyCookie(proxyCookie)
	if err != nil {
		return nil, err
	}

	return &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 pubkey,
		sessionCookieTimestamp: timestamp,
	}, nil
}

// Refreshes the session cookie, given a proxy cookie and a proof-of-possession
// of the private key. Returns just the new session cookie; the proxy cookie
// should not be changed for a refresh. Also returns the public key string
// for logging purposes.
func Refresh(proxyCookie *http.Cookie, jwtProof string) (*http.Cookie, string, error) {
	// Decrypt the proxy cookie
	upstreamCookie, pubkey, err := decryptProxyCookie(proxyCookie)
	if err != nil {
		return nil, "", err
	}

	// Verify the proof-of-possession
	err = dbscchallenge.VerifyFromJWT(jwtProof, pubkey)
	if err != nil {
		return nil, "", err
	}

	// Generate a new session cookie with an updated timestamp
	sess := &SecureSession{
		upstreamCookie:         upstreamCookie,
		pubkey:                 pubkey,
		sessionCookieTimestamp: dbsctime.Now(),
	}

	pubkeyString, err := sess.PubkeyString()
	if err != nil {
		return nil, "", err
	}

	return sess.buildSessionCookie(proxyCookie), pubkeyString, nil
}

func (sess *SecureSession) ToCookies() (proxyCookie *http.Cookie, sessionCookie *http.Cookie, err error) {
	// Encrypt the proxy cookie

	pubkey, err := sess.PubkeyString()
	if err != nil {
		return nil, nil, err
	}

	proxyCookieData, err := json.Marshal(&proxyCookieData{
		UpstreamSession: sess.upstreamCookie.String(),
		Pubkey:          pubkey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid proxy cookie data: %w", err)
	}

	proxyCookieEncrypted, err := EncryptToString(&config.ProxyCookieEncryptionSecret, proxyCookieData)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not encrypt cookie: %w", err)
	}

	proxyCookie = &http.Cookie{
		Name:        config.ProxyCookieName,
		Value:       proxyCookieEncrypted,
		Path:        sess.upstreamCookie.Path,
		Domain:      sess.upstreamCookie.Domain,
		Expires:     sess.upstreamCookie.Expires,
		MaxAge:      sess.upstreamCookie.MaxAge,
		Secure:      sess.upstreamCookie.Secure,
		HttpOnly:    sess.upstreamCookie.HttpOnly,
		SameSite:    sess.upstreamCookie.SameSite,
		Partitioned: sess.upstreamCookie.Partitioned,
	}

	// Generate the short-lived session cookie
	sessionCookie = sess.buildSessionCookie(proxyCookie)

	return
}

func (sess *SecureSession) buildSessionCookie(proxyCookie *http.Cookie) *http.Cookie {
	timestampString := strconv.FormatInt(sess.sessionCookieTimestamp.Unix(), 10)
	toSign := timestampString + ":" + proxyCookie.Value
	signature := auth.Sum([]byte(toSign), &config.SessionCookieSigningSecret)
	sessionCookieValue := config.SessionCookiePrefix + timestampString + ":" + base64.URLEncoding.EncodeToString(signature[:])

	sessionCookieAge := dbsctime.Since(sess.sessionCookieTimestamp)

	return &http.Cookie{
		Name:   config.Global.CookieName,
		Value:  sessionCookieValue,
		MaxAge: int(config.Global.RefreshInterval.Seconds() - sessionCookieAge.Seconds()),

		Path:        sess.upstreamCookie.Path,
		Domain:      sess.upstreamCookie.Domain,
		Secure:      sess.upstreamCookie.Secure,
		HttpOnly:    sess.upstreamCookie.HttpOnly,
		SameSite:    sess.upstreamCookie.SameSite,
		Partitioned: sess.upstreamCookie.Partitioned,
	}
}

func (sess *SecureSession) PubkeyString() (string, error) {
	if sess.pubkey.Curve != elliptic.P256() {
		// We only support P256 curves (and don't store the curve in the cookie)
		// so validate that here so we can't accidentally store parameters for
		// the wrong curve
		return "", errors.New("Invalid public key curve")
	}

	pubkeyBytes, err := sess.pubkey.Bytes()
	if err != nil {
		return "", fmt.Errorf("Invalid public key: %w", err)
	}

	return base64.URLEncoding.EncodeToString(pubkeyBytes), nil
}

func (sess *SecureSession) CookieForUpstream() *http.Cookie {
	return &http.Cookie{
		Name:  sess.upstreamCookie.Name,
		Value: sess.upstreamCookie.Value,
	}
}

func (sess *SecureSession) WithNewUpstreamCookie(newCookie *http.Cookie) *SecureSession {
	return &SecureSession{
		upstreamCookie:         newCookie,
		pubkey:                 sess.pubkey,
		sessionCookieTimestamp: sess.sessionCookieTimestamp,
		// Clear incomingProxyCookie; we must issue a new one
	}
}

func GenerateRegistrationAuthorization(upstreamCookie *http.Cookie, challenge string) (string, error) {
	data := &registrationAuthorizationData{
		UpstreamCookie: upstreamCookie.String(),
		Challenge:      challenge,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return EncryptToString(&config.RegistrationAuthorizationEncryptionSecret, jsonData)
}
