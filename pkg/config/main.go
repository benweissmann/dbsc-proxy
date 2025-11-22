package config

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"time"

	"github.com/caarlos0/env/v11"
)

// Static config
const ProxyCookieName = "dbsc_proxy"
const SessionCookieFirstPart = "dbsc_proxy"
const SessionCookiePrefix = SessionCookieFirstPart + ":"
const DbscSessionId = "dbsc_proxy"

// How expired does a session cookie need to be before we reject it? We don't
// want to reject a session cookie that was valid when it was sent (since the
// browser isn't required to refresh until the expiration) but took some time
// to arrive, so we give a 30 second buffer to permit transmission delays
const SessionCookieEnforcementSlop = time.Second * 30

type Config struct {
	Secret          string          `env:"DBSC_PROXY_SECRET,required"`
	Upstream        url.URL         `env:"DBSC_PROXY_UPSTREAM,required"`
	Listen          string          `env:"DBSC_PROXY_LISTEN" envDefault:"0.0.0.0:8000"`
	CookieName      string          `env:"DBSC_PROXY_COOKIE_NAME" envDefault:"session"`
	Scope           json.RawMessage `env:"DBSC_PROXY_SCOPE"`
	RefreshInterval time.Duration   `env:"DBSC_PROXY_REFRESH_INTERVAL" envDefault:"15m"`
	SetXForwarded   bool            `env:"DBSC_PROXY_SET_X_FORWARDED"`
	RewriteHost     bool            `env:"DBSC_PROXY_REWRITE_HOST"`
}

var Global Config

var SigningSecret [32]byte
var EncryptionSecret [32]byte

func ParseEnv() error {
	err := env.ParseWithOptions(&Global, env.Options{
		FuncMap: map[reflect.Type]env.ParserFunc{
			reflect.TypeOf(json.RawMessage{}): func(value string) (interface{}, error) {
				valueBytes := []byte(value)

				if !json.Valid(valueBytes) {
					return nil, fmt.Errorf("Environment variable has invalid JSON: %s", value)
				}

				return json.RawMessage(valueBytes), nil
			},
			reflect.TypeOf(url.URL{}): func(value string) (interface{}, error) {
				u, err := url.ParseRequestURI(value)
				if err != nil {
					return nil, err
				}

				if u.User != nil {
					return nil, fmt.Errorf("Upstream URL must not contain user: %s", value)
				}

				if u.Path != "" {
					return nil, fmt.Errorf("Upstream URL must not contain path: %s", value)
				}

				if u.RawQuery != "" {
					return nil, fmt.Errorf("Upstream URL must not contain query: %s", value)
				}

				if u.Scheme != "http" && u.Scheme != "https" {
					return nil, fmt.Errorf("Upstream URL must be a http:// or https:// URL: %s", value)
				}

				return *u, nil
			},
		},
	})

	if err != nil {
		return err
	}

	if len(Global.Secret) < 32 {
		// We actually care about it having 32 bytes of entropy (so a 32-character
		// hex encoding, for example, would be too short). But we don't know how
		// it's encoded, so we can only verify that the string is at least 32 bytes
		// long to give us a lower bound.
		return errors.New("DBSC_PROXY_SECRET must be at least 32 characters long")
	}

	keys, err := hkdf.Key(sha256.New, []byte(Global.Secret), nil, "", 64)
	if err != nil {
		return err
	}

	copy(EncryptionSecret[:], keys[0:32])
	copy(SigningSecret[:], keys[32:64])

	return nil
}
