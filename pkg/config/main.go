package config

import (
	"github.com/caarlos0/env"
)

type DBSCScope struct {
	origin             string                   `json:"origin",omitempty`
	includeSite        bool                     `json:"include_site"`
	scopeSpecification []DBSCScopeSpecification `json:"scope_specification",omitempty`
}

type DBSCScopeSpecification struct {
	scopeSpecificationType string `json:"type"`
	host                   string `json:"host",omitempty`
	path                   string `json:"path",omitempty`
}

type Config struct {
	secret     string `env:"DBSC_PROXY_SECRET",required`
	cookieName string `env:"DBSC_PROXY_COOKIE_NAME",envDefault:"session"`
	scope      string `env:"DBSC_PROXY_SCOPE`
}

var config *Config

func ParseEnv() error {
	if err := env.Parse(&config); err != nil {
		return err
	}

}

func Get() *Config {
	return config
}
