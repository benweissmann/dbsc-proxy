package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"log/slog"

	"github.com/benweissmann/dbsc-proxy/pkg/config"
	"github.com/benweissmann/dbsc-proxy/pkg/dbscchallenge"
	"github.com/benweissmann/dbsc-proxy/pkg/dbscsession"
)

const ContextKey = "dbsc_session"

func logRequest(status string, req *http.Request, sess *dbscsession.SecureSession, responseAction string) {
	pubkeyString := ""
	if sess != nil {
		requestPubkey, err := sess.PubkeyString()
		if err == nil {
			pubkeyString = requestPubkey
		}
	}

	slog.Info("Handled request", "status", status, "method", req.Method, "path", req.URL.Path, "dbscPubkey", pubkeyString, "responseAction", responseAction)

}

func challengeHeaderValue() string {
	return fmt.Sprintf(`"%s";id="%s"`, dbscchallenge.NewChallenge().Sign(), config.DbscSessionId)
}

func setupProxyHandlers(mux *http.ServeMux) {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&config.Global.Upstream)

			if !config.Global.RewriteHost {
				// SetURL rewrites host by default
				r.Out.Host = r.In.Host
			}

			if config.Global.SetXForwarded {
				r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
				r.SetXForwarded()
			} else {
				r.Out.Header["Forwarded"] = r.In.Header["Forwarded"]
				r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
				r.Out.Header["X-Forwarded-Host"] = r.In.Header["X-Forwarded-Host"]
				r.Out.Header["X-Forwarded-Proto"] = r.In.Header["X-Forwarded-Proto"]
			}

			dbscProxyCookie, _ := r.In.Cookie("dbsc_proxy")
			sessionCookie, _ := r.In.Cookie(config.Global.CookieName)
			if dbscProxyCookie != nil && sessionCookie != nil && strings.HasPrefix(sessionCookie.Value, config.SessionCookiePrefix) {
				// The client has DBSC Proxy cookies -- try to load & validate the
				// session
				sess, err := dbscsession.LoadFromCookies(dbscProxyCookie, sessionCookie)
				if err != nil {
					slog.Warn("Failed to validate session from cookies", "err", err)
				} else {
					// Add the session to the request context
					r.Out = r.Out.WithContext(context.WithValue(r.Out.Context(), ContextKey, sess))

					// Swap out the cookies for upstream
					r.Out.Header.Del("Cookie")
					for _, cookie := range r.In.Cookies() {
						if cookie.Name == config.ProxyCookieName || cookie.Name == config.Global.CookieName {
							// don't pass along the proxy cookie or DBSC session cookie
							continue
						}

						r.Out.AddCookie(cookie)
					}
					r.Out.AddCookie(sess.CookieForUpstream())

					// Add the public key header
					pubkeyString, err := sess.PubkeyString()
					if err != nil {
						slog.Error("Unable to generate public key string", "err", err)
						pubkeyString = ""
					}
					r.Out.Header.Set("Dbsc-Proxy-Public-Key", pubkeyString)
				}
			}

			if r.Out.Context().Value(ContextKey) == nil {
				// no DBSC session -- clear any client-provided values
				r.Out.Header.Del("Dbsc-Proxy-Public-Key")

				// Filter DBSC cookies out
				r.Out.Header.Del("Cookie")
				for _, cookie := range r.In.Cookies() {
					if cookie.Name == config.ProxyCookieName {
						// don't pass along the proxy cookie
						continue
					}

					if cookie.Name == config.Global.CookieName && strings.HasPrefix(cookie.Value, config.SessionCookiePrefix) {
						// don't pass along session cookie if it was an invalid DBSC session cookie
						continue
					}

					r.Out.AddCookie(cookie)
				}
			}
		},
		ModifyResponse: func(r *http.Response) error {
			responseAction := "none"
			requestSess, _ := r.Request.Context().Value(ContextKey).(*dbscsession.SecureSession)

			var sessionSetCookie *http.Cookie
			for _, cookie := range r.Cookies() {
				if cookie.Name == config.Global.CookieName {
					sessionSetCookie = cookie
				}
			}

			if sessionSetCookie != nil {
				if SetCookieIsDelete(sessionSetCookie) {
					responseAction = "clear"
					// upstream is clearing the cookie; also clear our proxy cookie
					r.Header.Add("Set-Cookie", (&http.Cookie{
						Name:    config.ProxyCookieName,
						Value:   "",
						Expires: time.Unix(0, 0),
					}).String())
				} else if requestSess == nil {
					// upstream is setting a new session cookie; offer DBSC registration
					responseAction = "offer-registration"
					authorization, err := dbscsession.GenerateRegistrationAuthorization(sessionSetCookie)
					if err == nil {
						r.Header.Add(
							"Secure-Session-Registration",
							`(ES256);challenge="`+
								dbscchallenge.NewChallenge().Sign()+
								`";authorization="`+
								authorization+
								`";path="/dbsc_proxy/StartSession"`,
						)
					}
				} else {
					// upstream is changing the session cookie of an existing session
					newSess := requestSess.WithNewUpstreamCookie(sessionSetCookie)
					newProxyCookie, newSessCookie, err := newSess.ToCookies()
					if err != nil {
						slog.Error("Error generating new session cookie for modified upstream session", "err", err)
					} else {
						responseAction = "update-upstream-cookie"

						r.Header.Add("Set-Cookie", newProxyCookie.String())
						r.Header.Add("Set-Cookie", newSessCookie.String())
					}
				}
			}

			if requestSess != nil {
				// A session is active; give the browser a challenge in case it needs
				// to refresh the session
				r.Header.Add("Secure-Session-Challenge", challengeHeaderValue())
			}

			logRequest(r.Status, r.Request, requestSess, responseAction)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			slog.Warn("Error proxying request", "url", r.URL.String(), "error", e)
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	mux.HandleFunc("POST /dbsc_proxy/StartSession", func(w http.ResponseWriter, r *http.Request) {
		jws := r.Header.Get("Secure-Session-Response")
		if jws == "" {
			slog.Info("StartSession request lacked JWS")

			w.WriteHeader(http.StatusForbidden)
			return
		}

		pubkey, authorization, err := dbscchallenge.VerifyFromUserProvidedKey(jws)
		if err != nil {
			slog.Warn("StartSession failed to verify JWS", "err", err)

			w.WriteHeader(http.StatusForbidden)
			return
		}

		sess, err := dbscsession.CreateForPubkey(pubkey, authorization)
		if err != nil {
			slog.Warn("StartSession failed to validate authorization", "err", err)

			w.WriteHeader(http.StatusForbidden)
			return
		}

		proxyCookie, sessionCookie, err := sess.ToCookies()
		if err != nil {
			slog.Warn("StartSession failed to generate cookies", "err", err)

			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, proxyCookie)
		http.SetCookie(w, sessionCookie)

		json.NewEncoder(w).Encode(sess.RegistrationInstructions())

		logRequest("200 OK", r, sess, "startSession")
	})

	mux.HandleFunc("POST /dbsc_proxy/Refresh", func(w http.ResponseWriter, r *http.Request) {
		proxyCookie, _ := r.Cookie(config.ProxyCookieName)
		if proxyCookie == nil {
			w.WriteHeader(http.StatusForbidden)
			logRequest("403 Forbidden", r, nil, "noProxyCookie")
			return
		}

		jwt := r.Header.Get("Secure-Session-Response")
		if jwt == "" {
			w.Header().Add("Secure-Session-Challenge", challengeHeaderValue())
			w.WriteHeader(http.StatusForbidden)

			logRequest("403 Forbidden", r, nil, "sendChallenge")

			return
		}

		newSessionCookie, pubkeyString, err := dbscsession.Refresh(proxyCookie, jwt)
		if err != nil {
			slog.Warn("Refresh failed", "err", err)

			w.Header().Add("Secure-Session-Challenge", challengeHeaderValue())
			w.WriteHeader(http.StatusForbidden)
			return
		}

		http.SetCookie(w, newSessionCookie)
		w.WriteHeader(http.StatusNoContent)

		slog.Info("Handled request",
			"status", http.StatusNoContent,
			"method", r.Method,
			"path", r.URL.Path,
			"dbscPubkey", pubkeyString,
			"responseAction", "refreshSession")
	})
}

func main() {
	err := config.ParseEnv()
	if err != nil {
		panic(err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	mux := http.NewServeMux()
	setupProxyHandlers(mux)

	slog.Error("HTTP Server errored", "error", http.ListenAndServe(config.Global.Listen, mux))
}
