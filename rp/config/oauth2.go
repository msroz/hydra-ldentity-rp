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
	redirectURL      = env.Getenv("REDIRECT_URL", fmt.Sprintf("http://127.0.0.1:%s/callback", port))

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
