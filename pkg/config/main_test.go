package config

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func reset() {
	os.Clearenv()
	Global = Config{}
}

func mustParseUrl(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}

	return *u
}

func TestParseMinimal(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com")

	ParseEnv()

	assert.Equal(t, Config{
		Secret:          "foo123456789012345678901234567890",
		Upstream:        mustParseUrl("http://example.com"),
		Listen:          "0.0.0.0:8000",
		CookieName:      "session",
		Scope:           nil,
		RefreshInterval: time.Minute * 15,
		SetXForwarded:   false,
		RewriteHost:     false,
	}, Global)

	assert.Equal(t, "7be0f498f06e33026f60478a1bda8ea8880b3381042bf6e62dcae9b5ae7a3639", hex.EncodeToString(EncryptionSecret[:]))
	assert.Equal(t, "d6a5602426aab6835ff175573656c2cc54b095434e0d99e51cd30cf807bf6004", hex.EncodeToString(SigningSecret[:]))
}

func TestParseMaximal(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "https://1.2.3.4:1234")
	os.Setenv("DBSC_PROXY_LISTEN", "127.0.0.1:80")
	os.Setenv("DBSC_PROXY_COOKIE_NAME", "mycookie")
	os.Setenv("DBSC_PROXY_SCOPE", `{"some": "scope"}`)
	os.Setenv("DBSC_PROXY_REFRESH_INTERVAL", "1h")
	os.Setenv("DBSC_PROXY_SET_X_FORWARDED", "true")
	os.Setenv("DBSC_PROXY_REWRITE_HOST", "true")
	assert.NoError(t, ParseEnv())

	assert.Equal(t, Config{
		Secret:          "foo123456789012345678901234567890",
		Upstream:        mustParseUrl("https://1.2.3.4:1234"),
		Listen:          "127.0.0.1:80",
		CookieName:      "mycookie",
		Scope:           json.RawMessage(`{"some": "scope"}`),
		RefreshInterval: time.Hour,
		SetXForwarded:   true,
		RewriteHost:     true,
	}, Global)
}

func TestParseInvalidJson(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com")
	os.Setenv("DBSC_PROXY_SCOPE", `{"some": "bad scope"`)

	assert.ErrorContains(t, ParseEnv(), "Environment variable has invalid JSON: {\"some\": \"bad scope\"")
}

func TestParseMissingSecret(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com")

	assert.EqualError(t, ParseEnv(), "env: required environment variable \"DBSC_PROXY_SECRET\" is not set")
}

func TestParseMissingUpstream(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")

	assert.EqualError(t, ParseEnv(), "env: required environment variable \"DBSC_PROXY_UPSTREAM\" is not set")
}

func TestParseInvalidUpstreamUrl(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "example.com")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": parse \"example.com\": invalid URI for request")
}

func TestParseInvalidUpstreamHasPath(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com/foo")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must not contain path: http://example.com/foo")
}

func TestParseInvalidUpstreamHasQuery(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com?x=y")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must not contain query: http://example.com?x=y")
}

func TestParseInvalidUpstreamHasUser(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://foo:bar@example.com")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must not contain user: http://foo:bar@example.com")
}

func TestParseInvalidUpstreamBadScheme(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo123456789012345678901234567890")
	os.Setenv("DBSC_PROXY_UPSTREAM", "mailto:foo@example.com")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must be a http:// or https:// URL: mailto:foo@example.com")
}

func TestSecretTooShort(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "foo1234567890123456789012345678")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com")

	assert.EqualError(t, ParseEnv(), "DBSC_PROXY_SECRET must be at least 32 characters long")
}
