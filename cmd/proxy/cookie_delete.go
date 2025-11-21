package main

import (
	"net/http"

	"github.com/benweissmann/dbsc-proxy/pkg/dbsctime"
)

func SetCookieIsDelete(c *http.Cookie) bool {
	if c.MaxAge != 0 {
		// max-age take precedence if both are present
		return c.MaxAge < 0
	} else if !c.Expires.IsZero() {
		return c.Expires.Before(dbsctime.Now())
	}

	return false
}
