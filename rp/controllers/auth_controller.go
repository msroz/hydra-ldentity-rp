package controllers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"rp/auth"
	"rp/httputil"
	"rp/model"
	"rp/view"
	"time"

	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/ory/x/randx"
	"golang.org/x/oauth2"
)

const (
	loginSessionName    = "rp_login_session"
	authZReqSessionName = "rp_authz_req_session"
)

type AuthController struct {
	store       *sessions.CookieStore
	oauth2Conf  oauth2.Config
	tmplService *view.TemplateService
}

func NewAuthController(store *sessions.CookieStore, oauth2Conf oauth2.Config, tmplService *view.TemplateService) *AuthController {
	return &AuthController{
		store:       store,
		oauth2Conf:  oauth2Conf,
		tmplService: tmplService,
	}
}

func (c *AuthController) Initiate(w http.ResponseWriter, r *http.Request) {
	state, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		httputil.HandleError(w, "unable to generate state", http.StatusInternalServerError, err)
		return
	}
	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		httputil.HandleError(w, "unable to generate nonce", http.StatusInternalServerError, err)
		return
	}

	reqSession, _ := c.store.Get(r, authZReqSessionName)

	stateStr := string(state)
	nonceStr := string(nonce)

	reqSession.Values["state"] = stateStr
	reqSession.Values["nonce"] = nonceStr
	codeVerifier, _ := randx.RuneSequence(64, randx.AlphaLower)
	converted := sha256.Sum256([]byte(string(codeVerifier)))
	codeChallenge := base64.RawURLEncoding.EncodeToString(converted[:])
	reqSession.Values["code_verifier"] = string(codeVerifier)

	reqSession.Save(r, w)

	authZReqWithPromptLoginURL := c.buildAuthURL(c.oauth2Conf, stateStr, nonceStr, codeChallenge, "login")
	authZReqWithPromptRegistrationURL := c.buildAuthURL(c.oauth2Conf, stateStr, nonceStr, codeChallenge, "registration")
	authZReqWithPromptNoneURL := c.buildAuthURL(c.oauth2Conf, stateStr, nonceStr, codeChallenge, "none")
	authZReqWithoutPrompt := c.buildAuthURL(c.oauth2Conf, stateStr, nonceStr, codeChallenge, "")

	c.tmplService.RenderTemplate(w, "initiate.html", map[string]interface{}{
		"AuthZReqWithPromptLoginURL":        authZReqWithPromptLoginURL,
		"AuthZReqWithPromptRegistrationURL": authZReqWithPromptRegistrationURL,
		"AuthZReqWithPromptNoneURL":         authZReqWithPromptNoneURL,
		"AuthZReqWithoutPrompt":             authZReqWithoutPrompt,
	})
}

func (c *AuthController) buildAuthURL(conf oauth2.Config, state, nonce, codeChallenge, prompt string) string {
	if prompt == "" {
		return conf.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.SetAuthURLParam("prompt", prompt),
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	return conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", prompt),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *AuthController) InitiateNative(w http.ResponseWriter, r *http.Request) {
	state := "DUMMY"
	authZReqWithPromptLoginURL := c.oauth2Conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("ui_locales", "ja-JP"),
	)

	authZReqWithPromptRegistrationURL := c.oauth2Conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("prompt", "registration"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("ui_locales", "ja-JP"),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"loginURL":        authZReqWithPromptLoginURL,
		"registrationURL": authZReqWithPromptRegistrationURL,
	})
}

func (c *AuthController) Callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	scope := query.Get("scope")
	errCode := query.Get("error")
	errDesc := query.Get("error_description")

	var codeVerifier string
	reqSession, err := c.store.Get(r, authZReqSessionName)
	if err == nil && reqSession.Values["code_verifier"] != nil {
		codeVerifier = reqSession.Values["code_verifier"].(string)
	}

	c.tmplService.RenderTemplate(w, "callback_params.html", map[string]interface{}{
		"Code":             code,
		"State":            state,
		"Scope":            scope,
		"CodeVerifier":     codeVerifier,
		"Error":            errCode,
		"ErrorDescription": errDesc,
	})
}

func (c *AuthController) TokenExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	code := r.FormValue("code")

	reqSession, err := c.store.Get(r, authZReqSessionName)
	if err != nil {
		httputil.HandleError(w, "failed to get session", http.StatusInternalServerError, err)
		return
	}

	codeVerifierVal := reqSession.Values["code_verifier"]
	if codeVerifierVal == nil {
		httputil.HandleError(w, "code_verifier not found in session", http.StatusBadRequest, nil)
		return
	}
	codeVerifier, ok := codeVerifierVal.(string)
	if !ok {
		httputil.HandleError(w, "invalid code_verifier in session", http.StatusInternalServerError, nil)
		return
	}

	tokens, err := auth.TokenRequestWithPrivateKeyJwt(c.oauth2Conf, code, codeVerifier)
	if err != nil {
		httputil.HandleError(w, "unable to exchange code for token", http.StatusInternalServerError, err)
		return
	}

	set, err := auth.FetchHydraJWKs(ctx)
	if err != nil {
		httputil.HandleError(w, "failed to fetch JWKS", http.StatusInternalServerError, err)
		return
	}

	idTokenStr := tokens.Extra("id_token").(string)
	verifiedToken, err := jwt.ParseString(idTokenStr, jwt.WithKeySet(set, jws.WithRequireKid(true)))
	if err != nil {
		httputil.HandleError(w, "failed to verify JWS", http.StatusInternalServerError, err)
		return
	}

	if err := c.validateNonce(verifiedToken, reqSession); err != nil {
		httputil.HandleError(w, "nonce validation error", http.StatusInternalServerError, err)
		return
	}

	reqSession.Options.MaxAge = -1
	reqSession.Save(r, w)

	sub := verifiedToken.Subject()
	user := model.Store.FindOrCreateBySubject(&model.User{Subject: sub, IDToken: idTokenStr})

	if err := c.createLoginSession(w, r, user); err != nil {
		httputil.HandleError(w, "failed to save session", http.StatusInternalServerError, err)
		return
	}

	loginSession, _ := r.Cookie(loginSessionName)
	idTokenPayload, _ := json.MarshalIndent(verifiedToken, "", "  ")
	c.tmplService.RenderTemplate(w, "callback.html", map[string]interface{}{
		"AccessToken":    tokens.AccessToken,
		"RefreshToken":   tokens.RefreshToken,
		"Expiry":         tokens.Expiry.Format(time.RFC1123),
		"IDToken":        idTokenStr,
		"IDTokenPayload": string(idTokenPayload),
		"LoginSession":   loginSession,
	})
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
	session, _ := c.store.Get(r, loginSessionName)
	session.Values["user_id"] = int(user.ID)
	return session.Save(r, w)
}
