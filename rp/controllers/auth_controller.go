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
	"strconv"
	"strings"
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

type authzParams struct {
	state         string
	nonce         string
	codeChallenge string
}

func (c *AuthController) prepareAuthzRequest(w http.ResponseWriter, r *http.Request) (*authzParams, error) {
	state, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		return nil, fmt.Errorf("unable to generate state: %w", err)
	}
	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
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

	return &authzParams{state: stateStr, nonce: nonceStr, codeChallenge: codeChallenge}, nil
}

func (c *AuthController) AuthorizeForm(w http.ResponseWriter, r *http.Request) {
	params, err := c.prepareAuthzRequest(w, r)
	if err != nil {
		httputil.HandleError(w, err.Error(), http.StatusInternalServerError, err)
		return
	}

	data := map[string]interface{}{
		"Scope":         strings.Join(c.oauth2Conf.Scopes, " "),
		"Prompt":        "",
		"LoginHint":     "",
		"IDTokenHint":   "",
		"MaxAge":        "",
		"UserID":        "",
		"Subject":       "",
		"State":         params.state,
		"Nonce":         params.nonce,
		"CodeChallenge": params.codeChallenge,
	}

	if idStr := r.URL.Query().Get("user_id"); idStr != "" {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			httputil.HandleError(w, "invalid user_id parameter", http.StatusBadRequest, err)
			return
		}
		user, exists := model.Store.Find(model.ID(id))
		if !exists {
			httputil.HandleError(w, "user not found", http.StatusNotFound, nil)
			return
		}
		data["Prompt"] = "login"
		data["LoginHint"] = user.EmailVerified
		data["IDTokenHint"] = user.IDToken
		data["UserID"] = user.ID
		data["Subject"] = user.Subject
	}

	c.tmplService.RenderTemplate(w, "authorize.html", data)
}

func (c *AuthController) Authorize(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")

	conf := c.oauth2Conf
	if scope := r.FormValue("scope"); scope != "" {
		conf.Scopes = strings.Split(scope, " ")
	}

	prompt := r.FormValue("prompt")
	var extraParams []oauth2.AuthCodeOption
	if loginHint := r.FormValue("login_hint"); loginHint != "" {
		extraParams = append(extraParams, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	if idTokenHint := r.FormValue("id_token_hint"); idTokenHint != "" {
		extraParams = append(extraParams, oauth2.SetAuthURLParam("id_token_hint", idTokenHint))
	}
	if maxAge := r.FormValue("max_age"); maxAge != "" {
		extraParams = append(extraParams, oauth2.SetAuthURLParam("max_age", maxAge))
	}

	authURL := c.buildAuthURL(conf, state, nonce, codeChallenge, prompt, extraParams...)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (c *AuthController) buildAuthURL(conf oauth2.Config, state, nonce, codeChallenge, prompt string, extraParams ...oauth2.AuthCodeOption) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", prompt),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	opts = append(opts, extraParams...)
	return conf.AuthCodeURL(state, opts...)
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
	var emailVerified string
	if ev, ok := verifiedToken.Get("email_verified"); ok {
		emailVerified = fmt.Sprintf("%v", ev)
	}
	user := model.Store.FindOrCreateBySubject(&model.User{Subject: sub, IDToken: idTokenStr, EmailVerified: emailVerified})

	if err := c.createLoginSession(w, r, user); err != nil {
		httputil.HandleError(w, "failed to save session", http.StatusInternalServerError, err)
		return
	}

	loginSession, _ := r.Cookie(loginSessionName)
	idTokenPayload, _ := json.MarshalIndent(verifiedToken, "", "  ")

	var idTokenHeader string
	if parts := strings.SplitN(idTokenStr, ".", 3); len(parts) >= 1 {
		if headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
			var headerMap map[string]interface{}
			if err := json.Unmarshal(headerJSON, &headerMap); err == nil {
				pretty, _ := json.MarshalIndent(headerMap, "", "  ")
				idTokenHeader = string(pretty)
			}
		}
	}

	c.tmplService.RenderTemplate(w, "callback.html", map[string]interface{}{
		"AccessToken":    tokens.AccessToken,
		"RefreshToken":   tokens.RefreshToken,
		"Expiry":         tokens.Expiry.Format(time.RFC1123),
		"IDToken":        idTokenStr,
		"IDTokenHeader":  idTokenHeader,
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
