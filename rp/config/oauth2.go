package config

import (
	"fmt"
	"net/url"

	"github.com/ory/common/env"
	"github.com/ory/x/urlx"
	"golang.org/x/oauth2"
)

var (
	port             = env.Getenv("PORT", "7777")
	hydraAuthZReqURL = url.URL{Scheme: "http", Host: env.Getenv("HYDRA_AUTHZ_REQUEST_HOST", "127.0.0.1:8888")} // from RP UA to Hydra
	hydraTokenReqURL = url.URL{Scheme: "http", Host: env.Getenv("HYDRA_TOKEN_REQUEST_HOST", "hydra:8888")}     // from RP Server to Hydra
	hydraAdminURL    = url.URL{Scheme: "http", Host: env.Getenv("HYDRA_ADMIN_URL", "hydra:9999")}              // Hydra Admin API
	redirectURL      = env.Getenv("REDIRECT_URL", fmt.Sprintf("http://127.0.0.1:%s/callback", port))
	logoutCallbackURL  = env.Getenv("LOGOUT_CALLBACK_URL", fmt.Sprintf("http://127.0.0.1:%s/logout_callback", port))

	oauth2Conf oauth2.Config
)

// GetOAuth2Config returns the current OAuth2 configuration
func GetOAuth2Config() oauth2.Config {
	return oauth2Conf
}

// LoadOAuth2Config updates the OAuth2 configuration with new client credentials
func LoadOAuth2Config(id, secret string) {
	oauth2Conf = oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  urlx.AppendPaths(&hydraAuthZReqURL, "/oauth2/auth").String(),
			TokenURL: urlx.AppendPaths(&hydraTokenReqURL, "/oauth2/token").String(),
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"openid", "offline"},
	}
}

// GetPort returns the configured port
func GetPort() string {
	return port
}

// GetHydraSessionsLogoutURL returns the Hydra sessions logout URL (for UA-initiated logout)
func GetHydraSessionsLogoutURL() string {
	return urlx.AppendPaths(&hydraAuthZReqURL, "/oauth2/sessions/logout").String()
}

// GetHydraJWKSetURL returns the Hydra JWKS URL (for server-side JWK fetch)
func GetHydraJWKSetURL() string {
	return urlx.AppendPaths(&hydraTokenReqURL, "/.well-known/jwks.json").String()
}

// GetLogoutCallbackURL returns the post-logout redirect URI
func GetLogoutCallbackURL() string {
	return logoutCallbackURL
}

// GetHydraAdminIntrospectURL returns the Hydra Admin introspection endpoint URL
func GetHydraAdminIntrospectURL() string {
	return urlx.AppendPaths(&hydraAdminURL, "/admin/oauth2/introspect").String()
}
