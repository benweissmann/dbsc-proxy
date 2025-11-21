package dbscsession

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test RegistrationInstructions with Global.Scope set
func TestRegistrationInstructionsWithGlobalScope(t *testing.T) {
	setupTestSecrets()

	// Set a custom scope
	customScope := json.RawMessage(`{"custom":"scope","value":true}`)
	config.Global.Scope = customScope
	defer func() {
		config.Global.Scope = nil
	}()

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	// Test with cookie that has no domain
	cookieNoDomain := &http.Cookie{
		Name:  "session",
		Value: "test",
	}

	sessionNoDomain := SecureSession{
		upstreamCookie:         cookieNoDomain,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructions := sessionNoDomain.RegistrationInstructions()

	// Verify all fields
	assert.Equal(t, config.DbscSessionId, instructions.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructions.RefreshURL)
	assert.JSONEq(t, string(customScope), string(instructions.Scope))
	require.Len(t, instructions.Credentials, 1)
	assert.Equal(t, "cookie", instructions.Credentials[0].Type)
	assert.Equal(t, "session", instructions.Credentials[0].Name)

	// Test with cookie that has a domain
	cookieWithDomain := &http.Cookie{
		Name:   "session",
		Value:  "test",
		Domain: "example.com",
	}

	sessionWithDomain := SecureSession{
		upstreamCookie:         cookieWithDomain,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructionsWithDomain := sessionWithDomain.RegistrationInstructions()

	// Should still return the custom scope (Global.Scope takes precedence)
	assert.Equal(t, config.DbscSessionId, instructionsWithDomain.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructionsWithDomain.RefreshURL)
	assert.JSONEq(t, string(customScope), string(instructionsWithDomain.Scope))
	require.Len(t, instructionsWithDomain.Credentials, 1)
	assert.Equal(t, "cookie", instructionsWithDomain.Credentials[0].Type)
	assert.Equal(t, "session", instructionsWithDomain.Credentials[0].Name)
}

// Test RegistrationInstructions with cookie having Domain set
func TestRegistrationInstructionsWithDomain(t *testing.T) {
	setupTestSecrets()

	// Ensure Global.Scope is not set
	config.Global.Scope = nil

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	cookieWithDomain := &http.Cookie{
		Name:   "session",
		Value:  "test",
		Domain: "example.com",
	}

	session := SecureSession{
		upstreamCookie:         cookieWithDomain,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructions := session.RegistrationInstructions()

	// Verify all fields
	assert.Equal(t, config.DbscSessionId, instructions.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructions.RefreshURL)

	// Should return include_site:true
	expectedScope := json.RawMessage(`{"include_site":true}`)
	assert.JSONEq(t, string(expectedScope), string(instructions.Scope))

	require.Len(t, instructions.Credentials, 1)
	assert.Equal(t, "cookie", instructions.Credentials[0].Type)
	assert.Equal(t, "session", instructions.Credentials[0].Name)
}

// Test RegistrationInstructions without Domain set
func TestRegistrationInstructionsWithoutDomain(t *testing.T) {
	setupTestSecrets()

	// Ensure Global.Scope is not set
	config.Global.Scope = nil

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	cookieNoDomain := &http.Cookie{
		Name:  "session",
		Value: "test",
	}

	session := SecureSession{
		upstreamCookie:         cookieNoDomain,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructions := session.RegistrationInstructions()

	// Verify all fields
	assert.Equal(t, config.DbscSessionId, instructions.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructions.RefreshURL)

	// Should return include_site:false
	expectedScope := json.RawMessage(`{"include_site":false}`)
	assert.JSONEq(t, string(expectedScope), string(instructions.Scope))

	require.Len(t, instructions.Credentials, 1)
	assert.Equal(t, "cookie", instructions.Credentials[0].Type)
	assert.Equal(t, "session", instructions.Credentials[0].Name)
}

// Test RegistrationInstructions with empty Domain (should be treated as no domain)
func TestRegistrationInstructionsWithEmptyDomain(t *testing.T) {
	setupTestSecrets()

	// Ensure Global.Scope is not set
	config.Global.Scope = nil

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	cookieEmptyDomain := &http.Cookie{
		Name:   "session",
		Value:  "test",
		Domain: "",
	}

	session := SecureSession{
		upstreamCookie:         cookieEmptyDomain,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructions := session.RegistrationInstructions()

	// Verify all fields
	assert.Equal(t, config.DbscSessionId, instructions.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructions.RefreshURL)

	// Should return include_site:false (empty domain is treated as no domain)
	expectedScope := json.RawMessage(`{"include_site":false}`)
	assert.JSONEq(t, string(expectedScope), string(instructions.Scope))

	require.Len(t, instructions.Credentials, 1)
	assert.Equal(t, "cookie", instructions.Credentials[0].Type)
	assert.Equal(t, "session", instructions.Credentials[0].Name)
}

// Test RegistrationInstructions with cookie with all attributes
func TestRegistrationInstructionsWithAllAttributes(t *testing.T) {
	setupTestSecrets()

	// Ensure Global.Scope is not set
	config.Global.Scope = nil

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	cookieWithAllAttrs := &http.Cookie{
		Name:        "session",
		Value:       "test-value",
		Path:        "/app",
		Domain:      "example.com",
		Expires:     time.Now().Add(24 * time.Hour),
		MaxAge:      86400,
		Secure:      true,
		HttpOnly:    true,
		SameSite:    http.SameSiteStrictMode,
		Partitioned: true,
	}

	session := SecureSession{
		upstreamCookie:         cookieWithAllAttrs,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructions := session.RegistrationInstructions()

	// Verify all fields
	assert.Equal(t, config.DbscSessionId, instructions.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructions.RefreshURL)

	// Should return include_site:true (has domain)
	expectedScope := json.RawMessage(`{"include_site":true}`)
	assert.JSONEq(t, string(expectedScope), string(instructions.Scope))

	require.Len(t, instructions.Credentials, 1)
	assert.Equal(t, "cookie", instructions.Credentials[0].Type)
	assert.Equal(t, "session", instructions.Credentials[0].Name)

	// Check that attributes are extracted correctly
	// The cookie.String() format includes attributes after the first semicolon
	attrs := instructions.Credentials[0].Attributes
	assert.NotEmpty(t, attrs, "Attributes should not be empty for cookie with attributes")

	// Verify key attributes are present
	assert.Contains(t, attrs, "Path=/app")
	assert.Contains(t, attrs, "Domain=example.com")
	assert.Contains(t, attrs, "Secure")
	assert.Contains(t, attrs, "HttpOnly")
	assert.Contains(t, attrs, "SameSite=Strict")
	assert.Contains(t, attrs, "Partitioned")
}

// Test RegistrationInstructions with minimal cookie (only name and value)
func TestRegistrationInstructionsWithMinimalCookie(t *testing.T) {
	setupTestSecrets()

	// Ensure Global.Scope is not set
	config.Global.Scope = nil

	privKey, err := generateECDSAKey()
	require.NoError(t, err)

	minimalCookie := &http.Cookie{
		Name:  "session",
		Value: "test-value",
	}

	session := SecureSession{
		upstreamCookie:         minimalCookie,
		pubkey:                 &privKey.PublicKey,
		sessionCookieTimestamp: time.Now(),
	}

	instructions := session.RegistrationInstructions()

	// Verify all fields
	assert.Equal(t, config.DbscSessionId, instructions.SessionIdentifier)
	assert.Equal(t, "/dbsc_proxy/Refresh", instructions.RefreshURL)

	// Should return include_site:false (no domain)
	expectedScope := json.RawMessage(`{"include_site":false}`)
	assert.JSONEq(t, string(expectedScope), string(instructions.Scope))

	require.Len(t, instructions.Credentials, 1)
	assert.Equal(t, "cookie", instructions.Credentials[0].Type)
	assert.Equal(t, "session", instructions.Credentials[0].Name)

	// Check that attributes are empty for minimal cookie
	attrs := instructions.Credentials[0].Attributes
	assert.Empty(t, attrs, "Attributes should be empty for minimal cookie with only name and value")
}
