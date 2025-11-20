package config

import (
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
	os.Setenv("DBSC_PROXY_SECRET", "sosecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com")

	ParseEnv()

	assert.Equal(t, Config{
		Secret:          "sosecret",
		Upstream:        mustParseUrl("http://example.com"),
		Listen:          "0.0.0.0:8000",
		CookieName:      "session",
		Scope:           nil,
		RefreshInterval: time.Minute * 15,
		SetXForwarded:   false,
		RewriteHost:     false,
	}, Global)
}

func TestParseMaximal(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "https://1.2.3.4:1234")
	os.Setenv("DBSC_PROXY_LISTEN", "127.0.0.1:80")
	os.Setenv("DBSC_PROXY_COOKIE_NAME", "mycookie")
	os.Setenv("DBSC_PROXY_SCOPE", `{"some": "scope"}`)
	os.Setenv("DBSC_PROXY_REFRESH_INTERVAL", "1h")
	os.Setenv("DBSC_PROXY_SET_X_FORWARDED", "true")
	os.Setenv("DBSC_PROXY_REWRITE_HOST", "true")
	assert.NoError(t, ParseEnv())

	assert.Equal(t, Config{
		Secret:          "mysecret",
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
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
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
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")

	assert.EqualError(t, ParseEnv(), "env: required environment variable \"DBSC_PROXY_UPSTREAM\" is not set")
}

func TestParseInvalidUpstreamUrl(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "example.com")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": parse \"example.com\": invalid URI for request")
}

func TestParseInvalidUpstreamHasPath(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com/foo")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must not contain path: http://example.com/foo")
}

func TestParseInvalidUpstreamHasQuery(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://example.com?x=y")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must not contain query: http://example.com?x=y")
}

func TestParseInvalidUpstreamHasUser(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "http://foo:bar@example.com")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must not contain user: http://foo:bar@example.com")
}

func TestParseInvalidUpstreamBadScheme(t *testing.T) {
	reset()
	os.Setenv("DBSC_PROXY_SECRET", "mysecret")
	os.Setenv("DBSC_PROXY_UPSTREAM", "mailto:foo@example.com")

	assert.EqualError(t, ParseEnv(), "env: parse error on field \"Upstream\" of type \"url.URL\": Upstream URL must be a http:// or https:// URL: mailto:foo@example.com")
}
