package controllers

import (
	"encoding/json"
	"net/http"
	"os"
	"rp/config"

	"github.com/ory/common/env"
)

type ClientController struct{}

func NewClientController() *ClientController {
	return &ClientController{}
}

// SaveClient saves or resets the OAuth2 client configuration
func (c *ClientController) SaveClient(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("client_id")
	secret := r.FormValue("client_secret")

	if r.FormValue("submit") == "Reset" {
		id = os.Getenv("DEFAULT_CLIENT_ID")
		secret = os.Getenv("DEFAULT_CLIENT_SECRET")
	}

	config.LoadOAuth2Config(id, secret)
	http.Redirect(w, r, "/", http.StatusFound)
}

// GetJWKS handles the JWKS endpoint
func (c *ClientController) GetJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	file, err := os.Open("keys/public_key.jwk")
	if err != nil {
		http.Error(w, "Failed to open JWK file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	var jwkData map[string]interface{}
	if err := json.NewDecoder(file).Decode(&jwkData); err != nil {
		http.Error(w, "Failed to decode JWK file", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{jwkData}})
}

// GetAppleAppSiteAssociation handles the Apple App Site Association endpoint
func (c *ClientController) GetAppleAppSiteAssociation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	data := map[string]interface{}{
		"applinks": map[string]interface{}{
			"app": []interface{}{},
			"details": []map[string]interface{}{
				{
					"appID": env.Getenv("APPLE_APP_ID", "aaa"),
					"paths": []string{"/callback"},
				},
			},
		},
		"webcredentials": map[string]interface{}{
			"apps": []interface{}{"aaa"},
		},
	}

	json.NewEncoder(w).Encode(data)
}
