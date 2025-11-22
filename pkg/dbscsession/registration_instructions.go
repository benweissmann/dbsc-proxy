package dbscsession

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
)

type RegistrationInstructions struct {
	SessionIdentifier string                                `json:"session_identifier"`
	RefreshURL        string                                `json:"refresh_url"`
	Scope             json.RawMessage                       `json:"scope"`
	Credentials       []RegistrationInstructionsCredentials `json:"credentials"`
}

type RegistrationInstructionsCredentials struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Attributes string `json:"attributes"`
}

func (sess *SecureSession) RegistrationInstructions() *RegistrationInstructions {
	var scope json.RawMessage

	if config.Global.Scope != nil {
		scope = config.Global.Scope
	} else if sess.upstreamCookie.Domain != "" {
		scope = json.RawMessage(`{"include_site":true}`)
	} else {
		scope = json.RawMessage(`{"include_site":false}`)
	}

	attrCookie := *sess.upstreamCookie
	attrCookie.MaxAge = 0
	attrCookie.Expires = time.Time{}

	cookieValueAndAttrs := strings.SplitN(attrCookie.String(), "; ", 2)
	cookieAttrs := ""
	if len(cookieValueAndAttrs) == 2 {
		cookieAttrs = cookieValueAndAttrs[1]
	}

	return &RegistrationInstructions{
		SessionIdentifier: config.DbscSessionId,
		RefreshURL:        "/dbsc_proxy/Refresh",
		Scope:             scope,
		Credentials: []RegistrationInstructionsCredentials{
			{
				Type:       "cookie",
				Name:       config.Global.CookieName,
				Attributes: cookieAttrs,
			},
		},
	}
}
