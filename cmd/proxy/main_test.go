package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/benweissmann/dbsc-proxy/pkg/dbscchallenge"
	"github.com/benweissmann/dbsc-proxy/pkg/dbsctime"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// generateECDSAKey generates a test ECDSA key pair
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// createJWT creates a JWT signed with the given key
func createJWT(key *ecdsa.PrivateKey, challengeHeader string) (string, error) {
	// parse challenge header
	re := regexp.MustCompile(`"([^"]+)";id="dbsc_proxy"`)
	matches := re.FindStringSubmatch(challengeHeader)
	challenge := matches[1]

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		return "", err
	}

	payload := dbscchallenge.ChallengeSolutionPayload{
		Jti: challenge,
	}

	token, err := jwt.Signed(signer).Claims(payload).Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// createJWS creates a JWS with embedded public key for StartSession
func createJWS(key *ecdsa.PrivateKey, payload *dbscchallenge.ChallengeSolutionPayload) (string, error) {
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

func requireCookie(t *testing.T, resp *http.Response, name string) *http.Cookie {
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == name {
			cookie = c
			break
		}
	}
	require.NotNil(t, cookie, "Expected "+name+"cookie from upstream")

	return cookie
}

// extractChallengeFromHeader extracts challenge from Secure-Session-Registration or Secure-Session-Challenge header
func extractChallengeFromHeader(headerValue string) string {
	// For Secure-Session-Registration: (ES256);challenge="...";authorization="...";path="/dbsc_proxy/StartSession"
	// For Secure-Session-Challenge: just the challenge value
	if strings.Contains(headerValue, "challenge=\"") {
		start := strings.Index(headerValue, "challenge=\"") + len("challenge=\"")
		end := strings.Index(headerValue[start:], "\"")
		return headerValue[start : start+end]
	}
	return headerValue
}

// extractAuthorizationFromHeader extracts authorization from Secure-Session-Registration header
func extractAuthorizationFromHeader(headerValue string) string {
	if strings.Contains(headerValue, "authorization=\"") {
		start := strings.Index(headerValue, "authorization=\"") + len("authorization=\"")
		end := strings.Index(headerValue[start:], "\"")
		return headerValue[start : start+end]
	}
	return ""
}

// createMockUpstream creates a mock upstream server for testing
func createMockUpstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			// Simulate login - set a session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "sessionid",
				Value:    "upstream-session-token-123",
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
				Secure:   false,
				SameSite: http.SameSiteStrictMode,
			})
			w.Write([]byte("Login successful"))

		case "/login-multiple-cookies":
			// Set multiple cookies
			http.SetCookie(w, &http.Cookie{
				Name:     "sessionid",
				Value:    "upstream-session-123",
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
			})
			http.SetCookie(w, &http.Cookie{
				Name:   "preferences",
				Value:  "theme=dark",
				Path:   "/",
				MaxAge: 86400,
			})
			w.Write([]byte("Login successful"))

		case "/api/data":
			// Check that we received the upstream cookie
			cookie, err := r.Cookie("sessionid")
			if err != nil {
				if r.Header.Get("Dbsc-Proxy-Public-Key") != "" {
					panic("Got a public key with no sessionid cookie")
				}
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("No session cookie"))
				return
			}

			// Check for public key header
			pubkey := r.Header.Get("Dbsc-Proxy-Public-Key")

			w.Write([]byte(fmt.Sprintf("Data for session: %s, pubkey: %s", cookie.Value, pubkey)))

		case "/api/update-session":
			// Upstream changes the session cookie value
			http.SetCookie(w, &http.Cookie{
				Name:     "sessionid",
				Value:    "new-upstream-session-token-456",
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
				Secure:   false,
				SameSite: http.SameSiteStrictMode,
			})
			w.Write([]byte("Session updated"))

		case "/logout":
			// Upstream clears the session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "sessionid",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   false,
			})
			w.Write([]byte("Logged out"))

		case "/headers":
			// Report headers back to test
			xForwardedFor := r.Header.Get("X-Forwarded-For")
			xForwardedHost := r.Header.Get("X-Forwarded-Host")
			xForwardedProto := r.Header.Get("X-Forwarded-Proto")
			host := r.Host
			w.Write([]byte(fmt.Sprintf("Host: %s ||| X-Forwarded-For: %s ||| X-Forwarded-Host: %s ||| X-Forwarded-Proto: %s |||", host, xForwardedFor, xForwardedHost, xForwardedProto)))

		case "/cookies":
			// Report all cookies received
			cookies := r.Cookies()
			var cookieStrings []string
			for _, c := range cookies {
				cookieStrings = append(cookieStrings, fmt.Sprintf("%s=%s", c.Name, c.Value))
			}
			if len(cookieStrings) == 0 {
				w.Write([]byte("Cookies: (none)"))
			} else {
				w.Write([]byte(fmt.Sprintf("Cookies: %s", strings.Join(cookieStrings, ", "))))
			}

		case "/error-500":
			// Simulates an upstream error
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

type TestSetup struct {
	upstream         *httptest.Server
	proxy            *httptest.Server
	client           *http.Client
	clientPrivateKey *ecdsa.PrivateKey
	t                *testing.T
}

func createSetup(t *testing.T) *TestSetup {
	upstream := createMockUpstream()

	// Set environment variables
	os.Setenv("DBSC_PROXY_SECRET", "test-secret-key-with-at-least-32-characters-for-security")
	os.Setenv("DBSC_PROXY_UPSTREAM", upstream.URL)
	os.Setenv("DBSC_PROXY_COOKIE_NAME", "sessionid")
	os.Setenv("DBSC_PROXY_REFRESH_INTERVAL", "15m")

	// Parse config
	err := config.ParseEnv()
	require.NoError(t, err)

	// Setup the proxy
	proxyMux := http.NewServeMux()
	setupProxyHandlers(proxyMux)
	proxy := httptest.NewServer(proxyMux)

	// Create an HTTP client
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	// Create a key
	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	return &TestSetup{
		proxy:    proxy,
		upstream: upstream,
		client: &http.Client{
			Jar: jar,
		},
		clientPrivateKey: privKey,
		t:                t,
	}
}

func (s *TestSetup) Close() {
	s.upstream.Close()
	s.proxy.Close()
}

func (s *TestSetup) DoRequest(req *http.Request) (*http.Response, string) {
	resp, err := s.client.Do(req)
	require.NoError(s.t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(s.t, err)

	return resp, string(body)
}

func (s *TestSetup) Get(path string) (*http.Response, string) {
	req, err := http.NewRequest("GET", s.proxy.URL+path, nil)
	require.NoError(s.t, err)

	return s.DoRequest(req)
}

func (s *TestSetup) Post(path string) (*http.Response, string) {
	req, err := http.NewRequest("POST", s.proxy.URL+path, nil)
	require.NoError(s.t, err)

	return s.DoRequest(req)
}

func (s *TestSetup) PostHeaders(path string, headers map[string]string) (*http.Response, string) {
	req, err := http.NewRequest("POST", s.proxy.URL+path, nil)
	require.NoError(s.t, err)

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	return s.DoRequest(req)
}

func (s *TestSetup) GetHeaders(path string, headers map[string]string) (*http.Response, string) {
	req, err := http.NewRequest("GET", s.proxy.URL+path, nil)
	require.NoError(s.t, err)

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	return s.DoRequest(req)
}

func (s *TestSetup) GetCookies(path string, cookies []*http.Cookie) (*http.Response, string) {
	req, err := http.NewRequest("GET", s.proxy.URL+path, nil)
	require.NoError(s.t, err)

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	return s.DoRequest(req)
}

func (s *TestSetup) ClearCookies() {
	proxyUrl, err := url.Parse(s.proxy.URL)
	require.NoError(s.t, err)

	for _, cookie := range s.client.Jar.Cookies(proxyUrl) {
		s.client.Jar.SetCookies(proxyUrl, []*http.Cookie{
			{
				Name:   cookie.Name,
				Value:  "",
				MaxAge: -1,
			},
		})
	}
}

func (s *TestSetup) ClearCookie(name string) {
	proxyUrl, err := url.Parse(s.proxy.URL)
	require.NoError(s.t, err)

	s.client.Jar.SetCookies(proxyUrl, []*http.Cookie{
		{
			Name:   name,
			Value:  "",
			MaxAge: -1,
		},
	})
}

// TestHappyPath tests the complete DBSC flow
func TestHappyPath(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Login - triggers new session
	resp, _ := setup.Post("/login")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Check for registration header
	regHeader := resp.Header.Get("Secure-Session-Registration")
	require.NotEmpty(t, regHeader, "Expected Secure-Session-Registration header")
	require.Contains(t, regHeader, "ES256")
	require.NotContains(t, regHeader, "RS256")
	require.Contains(t, regHeader, `path="/dbsc_proxy/StartSession"`)

	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)
	require.NotEmpty(t, challenge, "Expected challenge in registration header")
	require.NotEmpty(t, authorization, "Expected authorization in registration header")

	// Check that we got the upstream session cookie
	require.Equal(t, "upstream-session-token-123", requireCookie(t, resp, "sessionid").Value)

	// Step 2: Register the session
	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, body := setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.JSONEq(t, `{
		"session_identifier": "dbsc_proxy",
		"refresh_url": "/dbsc_proxy/Refresh",

		"scope": {
			"include_site": false
		},

		"credentials": [{
			"type": "cookie",
			"name": "sessionid",
			"attributes": "Path=/; HttpOnly; SameSite=Strict"
		}]
	}`, body)

	// Check we got dbsc_proxy and sessionid cookies
	requireCookie(t, resp, "dbsc_proxy")
	require.True(t, strings.HasPrefix(requireCookie(t, resp, "sessionid").Value, "dbsc_proxy:"), "Session cookie should have dbsc_proxy prefix")
	require.False(t, strings.Contains(requireCookie(t, resp, "sessionid").Value, "upstream-session-token-123"), "Session cookie should not contain upstream value")

	// Step 3: Make a request in the session
	resp, body = setup.Get("/api/data")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, body, "upstream-session-token-123", "Upstream should receive original session")

	pubkeyBytes, err := setup.clientPrivateKey.PublicKey.Bytes()
	require.NoError(t, err)
	require.Contains(t, body, "pubkey: "+base64.URLEncoding.EncodeToString(pubkeyBytes), "Should have public key")

	// Check for challenge header
	challengeHeader := resp.Header.Get("Secure-Session-Challenge")
	require.NotEmpty(t, challengeHeader, "Expected Secure-Session-Challenge header")

	// Step 4: Session refresh: wait 20 minutes; session should be expired. Refresh
	// and it should be valid again
	dbsctime.MockAdvance(time.Minute * 20)

	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = setup.Post("/dbsc_proxy/Refresh")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	challengeHeader = resp.Header.Get("Secure-Session-Challenge")
	require.NotEmpty(t, challengeHeader, "Expected Secure-Session-Challenge header")

	jwt, err := createJWT(setup.clientPrivateKey, challengeHeader)
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/Refresh", map[string]string{
		"Secure-Session-Response": jwt,
	})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Check we got a new session cookie
	require.NotNil(t, requireCookie(t, resp, "sessionid"), "Expected refreshed session cookie")
	require.NotNil(t, requireCookie(t, resp, "dbsc_proxy"), "Expected refreshed proxy cookie")

	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Step 5: Upstream updates the session cookie. We advance 10 minutes,
	// and update the session cookie. Then, the upstream should get the new
	// value but if we advance another 6 minutes, the session should be
	// expired (checking that updating the session value does not update the
	// expiration
	dbsctime.MockAdvance(time.Minute * 10)
	resp, _ = setup.Post("/api/update-session")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Check we got updated cookies
	requireCookie(t, resp, "dbsc_proxy")
	requireCookie(t, resp, "sessionid")

	// Verify that a request now passes the updated session cookie upstream
	resp, body = setup.Get("/api/data")
	require.Contains(t, body, "new-upstream-session-token-456", "Upstream should receive updated session")
	require.Contains(t, body, "pubkey:", "Should have public key")

	dbsctime.MockAdvance(time.Minute * 6)
	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Step 6: Logout - clear the session
	resp, _ = setup.Post("/logout")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Check that both cookies are cleared
	clearedProxyCookie := requireCookie(t, resp, "dbsc_proxy")
	clearedSessionCookie := requireCookie(t, resp, "sessionid")

	require.True(t, clearedProxyCookie.MaxAge < 0 || clearedProxyCookie.Expires.Before(time.Now()), "Proxy cookie should be cleared")
	require.True(t, clearedSessionCookie.MaxAge < 0 || clearedSessionCookie.Expires.Before(time.Now()), "Proxy cookie should be cleared")
}

func TestStartSession_MissingJWS(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Try to start session without JWS
	resp, _ := setup.Post("/dbsc_proxy/StartSession")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestStartSession_InvalidJWS(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Try to start session with invalid JWS
	resp, _ := setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": "invalid.jws.token",
	})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestStartSession_InvalidAuthorization(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Get a registration challenge
	resp, _ := setup.Post("/login")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)

	// Create JWS with valid challenge but invalid authorization
	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: "invalid-authorization-token",
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRefresh_MissingProxyCookie(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Try to refresh without proxy cookie
	resp, _ := setup.Post("/dbsc_proxy/Refresh")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRefresh_NoSecureSessionResponse(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration first
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Try to refresh without Secure-Session-Response header
	resp, _ = setup.Post("/dbsc_proxy/Refresh")
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Should get a challenge back
	challengeHeader := resp.Header.Get("Secure-Session-Challenge")
	require.NotEmpty(t, challengeHeader, "Expected Secure-Session-Challenge header")
}

func TestRefresh_InvalidJWT(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration first
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Try to refresh with invalid JWT
	resp, _ = setup.PostHeaders("/dbsc_proxy/Refresh", map[string]string{
		"Secure-Session-Response": "invalid.jwt.token",
	})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRefresh_WrongKey(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration first
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Get a challenge
	resp, _ = setup.Post("/dbsc_proxy/Refresh")
	challengeHeader := resp.Header.Get("Secure-Session-Challenge")
	require.NotEmpty(t, challengeHeader)

	// Create JWT with wrong key
	wrongKey, err := generateECDSAKey()
	require.NoError(t, err)

	jwt, err := createJWT(wrongKey, challengeHeader)
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/Refresh", map[string]string{
		"Secure-Session-Response": jwt,
	})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRefresh_ExpiredChallenge(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration first
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Get a challenge
	resp, _ = setup.Post("/dbsc_proxy/Refresh")
	challengeHeader := resp.Header.Get("Secure-Session-Challenge")
	require.NotEmpty(t, challengeHeader)

	// Advance time to expire the challenge (challenges expire after 1 minute)
	dbsctime.MockAdvance(time.Second * 61)

	jwt, err := createJWT(setup.clientPrivateKey, challengeHeader)
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/Refresh", map[string]string{
		"Secure-Session-Response": jwt,
	})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestProxyRequest_NoDBSCSession(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Make a request without any DBSC session
	resp, body := setup.Get("/api/data")

	// Should still proxy the request, but without DBSC enhancements
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	require.Contains(t, body, "No session cookie")
}

func TestProxyRequest_InvalidSessionCookie(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Manually craft an invalid session cookie
	resp, _ := setup.GetCookies("/api/data", []*http.Cookie{
		{Name: "dbsc_proxy", Value: "invalid-data"},
		{Name: "sessionid", Value: "dbsc_proxy:invalid"},
	})

	// Should reject the request since session is invalid
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestProxyRequest_ExpiredSessionCookie(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Advance time past expiration
	dbsctime.MockAdvance(time.Minute * 20)

	// Request should fail due to expired session
	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestProxyRequest_MissingProxyCookie(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Make a request with session cookie but without proxy cookie
	setup.ClearCookie("dbsc_proxy")
	resp, _ = setup.Get("/api/data")

	// Should fail without the proxy cookie
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestProxyRequest_InvalidSignature(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Tamper with the session cookie to corrupt the signature
	proxyCookie := requireCookie(t, resp, "dbsc_proxy")
	sessionCookie := requireCookie(t, resp, "sessionid")

	resp, _ = setup.GetCookies("/api/data", []*http.Cookie{
		proxyCookie,
		{Name: "sessionid", Value: sessionCookie.Value + "tampered"},
	})

	// Should fail with invalid signature
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestProxyRequest_ClientProvidedHeaders(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Make a request with client-provided public key header (should be stripped).
	// Upsteram is set up to panic if it gets Dbsc-Proxy-Public-Key without
	// a valid session
	resp, body := setup.GetHeaders("/api/data", map[string]string{
		"Dbsc-Proxy-Public-Key": "fake-client-provided-key",
	})

	// Public key should be empty since no valid DBSC session
	require.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	require.Equal(t, body, "No session cookie")
}

func TestProxyResponse_OfferRegistration(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Login should offer registration
	resp, _ := setup.Post("/login")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	regHeader := resp.Header.Get("Secure-Session-Registration")
	require.NotEmpty(t, regHeader)
	require.Contains(t, regHeader, "ES256")
	require.Contains(t, regHeader, "challenge=")
	require.Contains(t, regHeader, "authorization=")
	require.Contains(t, regHeader, `path="/dbsc_proxy/StartSession"`)
}

func TestProxyResponse_ClearSession(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Logout should clear both cookies
	resp, _ = setup.Post("/logout")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	clearedProxyCookie := requireCookie(t, resp, "dbsc_proxy")
	clearedSessionCookie := requireCookie(t, resp, "sessionid")

	require.True(t, clearedProxyCookie.MaxAge < 0 || clearedProxyCookie.Expires.Before(time.Now()))
	require.True(t, clearedSessionCookie.MaxAge < 0 || clearedSessionCookie.Expires.Before(time.Now()))
}

func TestProxyResponse_UpdateUpstreamCookie(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Update session should update the cookies
	resp, _ = setup.Post("/api/update-session")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Should get updated cookies
	proxyCookie := requireCookie(t, resp, "dbsc_proxy")
	sessionCookie := requireCookie(t, resp, "sessionid")
	require.NotNil(t, proxyCookie)
	require.NotNil(t, sessionCookie)

	// Verify new session cookie is used upstream
	resp, body := setup.Get("/api/data")
	require.Contains(t, body, "new-upstream-session-token-456")
}

func TestProxyResponse_ChallengeHeader(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Any request with an active session should include a challenge header
	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	challengeHeader := resp.Header.Get("Secure-Session-Challenge")
	require.NotEmpty(t, challengeHeader, "Expected Secure-Session-Challenge header")
}

func TestXForwardedHeaders_SetXForwardedTrue(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Override config to enable X-Forwarded
	os.Setenv("DBSC_PROXY_SET_X_FORWARDED", "true")
	err := config.ParseEnv()
	require.NoError(t, err)

	// Make a request to test X-Forwarded headers
	resp, body := setup.Get("/headers")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// X-Forwarded headers should be set with actual values
	require.Contains(t, body, "X-Forwarded-For: 127.0.0.1")
	require.Regexp(t, "X-Forwarded-Host: 127\\.0\\.0\\.1:\\d+", body)
	require.Contains(t, body, "X-Forwarded-Proto: http")
}

func TestXForwardedHeaders_AppendsBehavior(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Override config to enable X-Forwarded
	os.Setenv("DBSC_PROXY_SET_X_FORWARDED", "true")
	err := config.ParseEnv()
	require.NoError(t, err)

	// Make a request with existing X-Forwarded-For header
	resp, body := setup.GetHeaders("/headers", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Should append to existing X-Forwarded-For (original IP, comma, then proxy IP)
	require.Regexp(t, "X-Forwarded-For: 1\\.2\\.3\\.4, 127\\.0\\.0\\.1", body)
}

func TestXForwardedHeaders_SetXForwardedFalse(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Ensure X-Forwarded is disabled (default)
	os.Setenv("DBSC_PROXY_SET_X_FORWARDED", "false")
	err := config.ParseEnv()
	require.NoError(t, err)

	// Make a request with existing X-Forwarded-For header
	_, body := setup.GetHeaders("/headers", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	})

	// Should preserve original X-Forwarded-For exactly without modification
	require.Contains(t, body, "X-Forwarded-For: 1.2.3.4")
	// Should NOT append proxy IP, so no comma followed by space and another IP
	require.NotRegexp(t, "X-Forwarded-For: 1\\.2\\.3\\.4, ", body)
	require.Contains(t, body, "X-Forwarded-Host:  |||")
	require.Contains(t, body, "X-Forwarded-Proto:  |||")
}

func TestHostHeader_RewriteHostTrue(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Override config to enable Host rewriting (default)
	os.Setenv("DBSC_PROXY_REWRITE_HOST", "true")
	err := config.ParseEnv()
	require.NoError(t, err)

	// Make a request
	resp, body := setup.Get("/headers")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Host should be rewritten to upstream host
	require.Contains(t, body, "Host: ")
	// Should contain the upstream host
	upstreamHost := strings.Split(setup.upstream.URL, "://")[1]
	require.Contains(t, body, upstreamHost)
}

func TestHostHeader_RewriteHostFalse(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Override config to disable Host rewriting
	os.Setenv("DBSC_PROXY_REWRITE_HOST", "false")
	err := config.ParseEnv()
	require.NoError(t, err)

	// Make a request
	resp, body := setup.Get("/headers")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Host should preserve the original proxy host
	require.Contains(t, body, "Host: ")
	proxyHost := strings.Split(setup.proxy.URL, "://")[1]
	require.Contains(t, body, proxyHost)
}

func TestCookieFiltering_NonDBSCCookies(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Make a request with non-DBSC cookies
	resp, body := setup.GetCookies("/cookies", []*http.Cookie{
		{Name: "other_cookie", Value: "value1"},
		{Name: "another_cookie", Value: "value2"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Non-DBSC cookies should be passed through
	require.Contains(t, body, "other_cookie=value1")
	require.Contains(t, body, "another_cookie=value2")
}

func TestCookieFiltering_DBSCCookiesFiltered(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Make a request with invalid DBSC cookies (without valid session)
	resp, body := setup.GetCookies("/cookies", []*http.Cookie{
		{Name: "dbsc_proxy", Value: "invalid"},
		{Name: "sessionid", Value: "dbsc_proxy:invalid"},
		{Name: "other_cookie", Value: "value1"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// DBSC cookies should be filtered out, other cookies should pass through
	require.NotContains(t, body, "dbsc_proxy")
	require.NotContains(t, body, "sessionid")
	require.Contains(t, body, "other_cookie=value1")
}

func TestMultipleCookies_OnlySessionModified(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Login to get multiple cookies
	resp, _ := setup.Post("/login-multiple-cookies")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Should get both cookies, sessionid and preferences
	var gotSession, gotPreferences bool
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "sessionid" {
			gotSession = true
		}
		if cookie.Name == "preferences" {
			gotPreferences = true
		}
	}
	require.True(t, gotSession, "Should get sessionid cookie")
	require.True(t, gotPreferences, "Should get preferences cookie")

	// Register DBSC session
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Make a request - verify that non-session cookies are passed through unchanged
	resp, body := setup.Get("/cookies")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Upstream should receive both sessionid and preferences
	require.Contains(t, body, "sessionid=upstream-session-123")
	require.Contains(t, body, "preferences=theme=dark")
}

func TestSessionCookieEnforcementSlop(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Complete a full session registration
	resp, _ := setup.Post("/login")
	regHeader := resp.Header.Get("Secure-Session-Registration")
	challenge := extractChallengeFromHeader(regHeader)
	authorization := extractAuthorizationFromHeader(regHeader)

	jws, err := createJWS(setup.clientPrivateKey, &dbscchallenge.ChallengeSolutionPayload{
		Jti:           challenge,
		Authorization: authorization,
	})
	require.NoError(t, err)

	resp, _ = setup.PostHeaders("/dbsc_proxy/StartSession", map[string]string{
		"Secure-Session-Response": jws,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Advance time to exactly 15 minutes (should still work)
	dbsctime.MockAdvance(time.Minute * 15)
	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusOK, resp.StatusCode, "Request at exactly 15min should succeed")

	// Advance time to 15 minutes + 29 seconds (within 30s grace period)
	dbsctime.MockAdvance(time.Second * 29)
	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusOK, resp.StatusCode, "Request within 30s grace period should succeed")

	// Advance time to 15 minutes + 31 seconds (beyond grace period)
	dbsctime.MockAdvance(time.Second * 2)
	resp, _ = setup.Get("/api/data")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Request beyond 30s grace period should fail")
}

func TestUpstreamError_Handling(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	// Test 500 error path
	resp, body := setup.Get("/error-500")
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	require.Contains(t, body, "Internal Server Error")
}

func TestConcurrentRequests(t *testing.T) {
	setup := createSetup(t)
	defer setup.Close()

	dbsctime.Mock(time.Now())
	defer dbsctime.MockReset()

	// Create 100 different clients with different keys
	const numClients = 100
	type clientInfo struct {
		privateKey *ecdsa.PrivateKey
		client     *http.Client
		pubkeyStr  string
	}

	clients := make([]*clientInfo, numClients)

	// Setup all clients
	for i := 0; i < numClients; i++ {
		// Generate unique key for this client
		privKey, err := generateECDSAKey()
		require.NoError(t, err)

		pubkeyBytes, err := privKey.PublicKey.Bytes()
		require.NoError(t, err)
		pubkeyStr := base64.URLEncoding.EncodeToString(pubkeyBytes)

		// Create isolated cookie jar for this client
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)

		clients[i] = &clientInfo{
			privateKey: privKey,
			client:     &http.Client{Jar: jar},
			pubkeyStr:  pubkeyStr,
		}

		// Register this client's session
		req, err := http.NewRequest("POST", setup.proxy.URL+"/login", nil)
		require.NoError(t, err)

		resp, err := clients[i].client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		regHeader := resp.Header.Get("Secure-Session-Registration")
		challenge := extractChallengeFromHeader(regHeader)
		authorization := extractAuthorizationFromHeader(regHeader)

		jws, err := createJWS(privKey, &dbscchallenge.ChallengeSolutionPayload{
			Jti:           challenge,
			Authorization: authorization,
		})
		require.NoError(t, err)

		req, err = http.NewRequest("POST", setup.proxy.URL+"/dbsc_proxy/StartSession", nil)
		require.NoError(t, err)
		req.Header.Set("Secure-Session-Response", jws)

		resp, err = clients[i].client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Now make concurrent requests and verify each gets the correct pubkey back
	done := make(chan bool, numClients)
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(clientID int, info *clientInfo) {
			req, err := http.NewRequest("GET", setup.proxy.URL+"/api/data", nil)
			if err != nil {
				errors <- fmt.Errorf("Client %d failed to create request: %v", clientID, err)
				done <- true
				return
			}

			resp, err := info.client.Do(req)
			if err != nil {
				errors <- fmt.Errorf("Client %d failed request: %v", clientID, err)
				done <- true
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("Client %d got status %d", clientID, resp.StatusCode)
				done <- true
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errors <- fmt.Errorf("Client %d failed to read body: %v", clientID, err)
				done <- true
				return
			}

			bodyStr := string(body)
			expectedPubkey := "pubkey: " + info.pubkeyStr
			if !strings.Contains(bodyStr, expectedPubkey) {
				errors <- fmt.Errorf("Client %d got wrong pubkey. Expected %s, got: %s",
					clientID, expectedPubkey, bodyStr)
				done <- true
				return
			}

			done <- true
		}(i, clients[i])
	}

	// Wait for all requests to complete
	for i := 0; i < numClients; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}
