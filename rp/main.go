package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ory/common/env"
	"github.com/ory/x/randx"
	"github.com/ory/x/urlx"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	port = "5555"
)

var (
	clientID     string
	clientSecret string

	hydraAuthZReqURL url.URL = url.URL{Scheme: "http", Host: "127.0.0.1:4444"} // from RP UA to Hydra
	hydraTokenReqURL url.URL = url.URL{Scheme: "http", Host: "hydra:4444"}     // from RP Server to Hydra

	redirectURL string = fmt.Sprintf("http://127.0.0.1:%s/callback", port)
)

func init() {
	clientID = os.Getenv("CLIENT_ID")
	if clientID == "" {
		log.Fatal("CLIENT_ID environment variable not set")
	}

	clientSecret = os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("CLIENT_SECRET environment variable not set")
	}

	fmt.Printf("[RP]============> clientID: %s\nclientSecret: %s\n", clientID, clientSecret)
}

func main() {
	r := chi.NewRouter()

	r.Get("/", home)
	r.Get("/initiate", initiate)
	r.Get("/callback", callback)

	log.Println("Listening on :" + env.Getenv("PORT", port))
	log.Fatal(http.ListenAndServe(":"+env.Getenv("PORT", port), r))
}

/*
Request handlers
*/

func home(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "home.html", map[string]interface{}{
		"ClientID":     clientID,
		"ClientSecret": clientSecret,
	})
}

func initiate(w http.ResponseWriter, r *http.Request) {

	conf := oauth2Config()
	state, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to generate state: %s\n", err)

		w.WriteHeader(http.StatusInternalServerError)
	}
	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to generate nonce: %s\n", err)

		w.WriteHeader(http.StatusInternalServerError)
	}
	authZRequestURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", ""),
		oauth2.SetAuthURLParam("max_age", "0"),
	)

	renderTemplate(w, "initiate.html", map[string]interface{}{
		"AuthZRequestURL": authZRequestURL,
	})

}

func callback(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query().Get("error")) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Got error: %s\n", r.URL.Query().Get("error_description"))

		w.WriteHeader(http.StatusInternalServerError)

		// TODO: error
		return
	}

	code := r.URL.Query().Get("code")
	conf := oauth2Config()
	token, err := conf.Exchange(r.Context(), code)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to exchange code for token: %s\n", err)

		w.WriteHeader(http.StatusInternalServerError)

		// TODO: error
		return
	}

	// Check nonce, state

	fmt.Printf("token: %#v\n", token)

	renderTemplate(w, "callback.html", map[string]interface{}{
		"Token":        token,
		"AccessToken":  token.AccessToken,
		"RefreshToken": token.RefreshToken,
		"Expiry":       token.Expiry.Format(time.RFC1123),
		"IDToken":      fmt.Sprintf("%s", token.Extra("id_token")),
	})

}

/*
	Internal functions
*/

func oauth2Config() oauth2.Config {
	return oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  urlx.AppendPaths(&hydraAuthZReqURL, "/oauth2/auth").String(),
			TokenURL: urlx.AppendPaths(&hydraTokenReqURL, "/oauth2/token").String(),
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"openid", "offline"},
	}
}

func renderTemplate(w http.ResponseWriter, id string, d interface{}) bool {
	if t, err := template.New(id).ParseFiles("./templates/" + id); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	} else if err := t.Execute(w, d); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

func pointer[T any](v T) *T { return &v }
