package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"time"

	"github.com/caarlos0/env/v11"
)

type DBSCProxyScope map[string]interface{}

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

func ParseEnv() error {
	return env.ParseWithOptions(&Global, env.Options{
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
}
