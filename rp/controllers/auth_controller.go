package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"rp/auth"
	"rp/config"
	"rp/model"
	"strconv"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/ory/x/randx"
	"github.com/ory/x/urlx"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	loginSessionName    = "rp_login_session"
	authZReqSessionName = "rp_authz_req_session"
)

var store = sessions.NewCookieStore([]byte("keep-session-store-key-secret"))

type AuthController struct{}

func NewAuthController() *AuthController {
	return &AuthController{}
}

func (c *AuthController) Initiate(w http.ResponseWriter, r *http.Request) {
	conf := config.GetOAuth2Config()
	state, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to generate state: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to generate nonce: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqSession, _ := store.Get(r, authZReqSessionName)

	stateStr := string(state)
	nonceStr := string(nonce)

	// state - CSRF protection
	reqSession.Values["state"] = stateStr
	// nonce - replay attack protection
	reqSession.Values["nonce"] = nonceStr
	// PKCE - 認可コード横取り対策
	codeVerifier, _ := randx.RuneSequence(64, randx.AlphaLower)
	converted := sha256.Sum256([]byte(string(codeVerifier)))
	codeChallenge := base64.RawURLEncoding.EncodeToString(converted[:])
	reqSession.Values["code_verifier"] = string(codeVerifier)

	reqSession.Save(r, w)

	authZReqWithPromptLoginURL := c.buildAuthURL(conf, stateStr, nonceStr, codeChallenge, "login")
	authZReqWithPromptRegistrationURL := c.buildAuthURL(conf, stateStr, nonceStr, codeChallenge, "registration")
	authZReqWithPromptNoneURL := c.buildAuthURL(conf, stateStr, nonceStr, codeChallenge, "none")

	renderTemplate(w, "initiate.html", map[string]interface{}{
		"AuthZReqWithPromptLoginURL":        authZReqWithPromptLoginURL,
		"AuthZReqWithPromptRegistrationURL": authZReqWithPromptRegistrationURL,
		"AuthZReqWithPromptNoneURL":         authZReqWithPromptNoneURL,
	})
}

func (c *AuthController) buildAuthURL(conf oauth2.Config, state, nonce, codeChallenge, prompt string) string {
	return conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", prompt),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *AuthController) InitiateNative(w http.ResponseWriter, r *http.Request) {
	conf := config.GetOAuth2Config()
	state := "DUMMY"
	authZReqWithPromptLoginURL := conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
	)

	authZReqWithPromptRegistrationURL := conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("prompt", "registration"),
		oauth2.SetAuthURLParam("max_age", "0"),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"loginURL":        authZReqWithPromptLoginURL,
		"registrationURL": authZReqWithPromptRegistrationURL,
	})
}

func (c *AuthController) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(r.URL.Query().Get("error")) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Got error: %s\n", r.URL.Query().Get("error_description"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	state := r.URL.Query().Get("state")
	reqSession, _ := store.Get(r, authZReqSessionName)
	if reqSession.IsNew {
		fmt.Printf("session not found\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := c.validateState(state, reqSession); err != nil {
		fmt.Printf("state validation error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")
	codeVerifier := reqSession.Values["code_verifier"].(string)
	conf := config.GetOAuth2Config()

	tokens, err := auth.TokenRequestWithPrivateKeyJwt(conf, code, codeVerifier)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to exchange code for token: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	set, err := c.fetchJWKs(ctx)
	if err != nil {
		fmt.Printf("failed to fetch JWKS: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	idTokenStr := tokens.Extra("id_token").(string)
	verifiedToken, err := jwt.ParseString(idTokenStr, jwt.WithKeySet(set, jws.WithRequireKid(true)))
	if err != nil {
		fmt.Printf("failed to verify JWS: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := c.validateNonce(verifiedToken, reqSession); err != nil {
		fmt.Printf("nonce validation error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// 認可リクエストのセッションを削除
	reqSession.Options.MaxAge = -1
	reqSession.Save(r, w)

	sub := verifiedToken.Subject()
	user := model.Store.FindOrCreateBySubject(&model.User{Subject: sub, IDToken: idTokenStr})

	// Login sessionの発行
	if err := c.createLoginSession(w, r, user); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save session: %v", err), http.StatusInternalServerError)
		return
	}

	loginSession, _ := r.Cookie(loginSessionName)
	idTokenPayload, _ := json.MarshalIndent(verifiedToken, "", "  ")
	renderTemplate(w, "callback.html", map[string]interface{}{
		"AccessToken":    tokens.AccessToken,
		"RefreshToken":   tokens.RefreshToken,
		"Expiry":         tokens.Expiry.Format(time.RFC1123),
		"IDToken":        idTokenStr,
		"IDTokenPayload": string(idTokenPayload),
		"LoginSession":   loginSession,
	})
}

func (c *AuthController) validateState(state string, session *sessions.Session) error {
	stateInSession := session.Values["state"].(string)
	if state != stateInSession {
		return fmt.Errorf("state not match")
	}
	return nil
}

func (c *AuthController) validateNonce(token jwt.Token, session *sessions.Session) error {
	n, exist := token.Get("nonce")
	if !exist {
		return fmt.Errorf("nonce not found")
	}
	nonce, ok := n.(string)
	if !ok {
		return fmt.Errorf("nonce is not string")
	}

	nonceInSession := session.Values["nonce"].(string)
	if nonce != nonceInSession {
		return fmt.Errorf("nonce not match %s != %s", nonce, nonceInSession)
	}
	return nil
}

func (c *AuthController) createLoginSession(w http.ResponseWriter, r *http.Request, user *model.User) error {
	session, _ := store.Get(r, loginSessionName)
	session.Values["user_id"] = int(user.ID)
	return session.Save(r, w)
}

func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	id, _ := strconv.Atoi(query.Get("id"))

	usr, exist := model.Store.Find(model.ID(id))
	err := ""
	if !exist {
		err = "User not found"
	}

	hydraAuthZReqURL := url.URL{Scheme: "http", Host: "127.0.0.1:8888"}
	u := urlx.AppendPaths(&hydraAuthZReqURL, "/oauth2/sessions/logout")
	u = urlx.SetQuery(u, url.Values{
		"id_token_hint":            []string{usr.IDToken},
		"post_logout_redirect_uri": []string{"http://127.0.0.1:7777/logout_callback"},
		"client_id":                []string{config.GetOAuth2Config().ClientID},
	})

	renderTemplate(w, "logout.html", map[string]interface{}{
		"LogoutURL": u.String(),
		"Error":     err,
	})
}

func (c *AuthController) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	fmt.Printf("state: %s\n", state)
	// TODO: Check state

	session, _ := store.Get(r, loginSessionName)
	session.Options.MaxAge = -1
	session.Save(r, w)

	renderTemplate(w, "complete_logout.html", map[string]interface{}{})
}

func (c *AuthController) BackchannelLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	logoutToken := r.FormValue("logout_token")
	set, err := c.fetchJWKs(ctx)
	if err != nil {
		fmt.Printf("failed to fetch JWKS: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	verifiedToken, err := jwt.ParseString(logoutToken, jwt.WithKeySet(set, jws.WithRequireKid(true)))
	if err != nil {
		fmt.Printf("failed to verify JWS: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s, exist := verifiedToken.Get("sid")
	if !exist {
		fmt.Printf("sid not found\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sid, ok := s.(string)
	if !ok {
		fmt.Printf("sid is not string\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Printf("backchannelLogout > sid: %s\n", sid)
	w.WriteHeader(http.StatusOK)
}

func (c *AuthController) fetchJWKs(ctx context.Context) (jwk.Set, error) {
	return jwk.Fetch(ctx, "http://hydra:8888/.well-known/jwks.json")
}

func renderTemplate(w http.ResponseWriter, id string, d interface{}) bool {
	t, err := template.New(id).ParseFiles("./templates/" + id)
	if err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	if err := t.Execute(w, d); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	return true
}
