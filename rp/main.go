package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"rp/auth"
	"rp/model"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/ory/common/env"
	"github.com/ory/x/randx"
	"github.com/ory/x/urlx"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	loginSessionName    = "rp_login_session"
	authZReqSessionName = "rp_authz_req_session"
)

var (
	oauth2Conf oauth2.Config

	port             string  = env.Getenv("PORT", "5555")
	hydraAuthZReqURL url.URL = url.URL{Scheme: "http", Host: env.Getenv("HYDRA_AUTHZ_REQUEST_HOST", "127.0.0.1:4444")} // from RP UA to Hydra
	hydraTokenReqURL url.URL = url.URL{Scheme: "http", Host: env.Getenv("HYDRA_TOKEN_REQUEST_HOST", "hydra:4444")}     // from RP Server to Hydra

	redirectURL string = env.Getenv("REDIRECT_URL", fmt.Sprintf("http://127.0.0.1:%s/callback", port))

	store = sessions.NewCookieStore([]byte("keep-session-store-key-secret"))
)

func init() {
	id := os.Getenv("DEFAULT_CLIENT_ID")
	sec := os.Getenv("DEFAULT_CLIENT_SECRET")
	loadOAuth2Config(id, sec)
}

func main() {
	r := chi.NewRouter()

	r.Get("/", home)
	r.Get("/initiate", initiate)
	r.Get("/callback", authzReqCallback)
	r.Get("/logout", logout)
	r.Get("/logout_callback", logoutCallback)
	r.Post("/backchannel_logout", backchannelLogout)

	r.Get("/.well-known/jwks.json", jwksHandler)

	r.Post("/clients", saveClient)

	// For Universal Links (iOS)
	r.Get("/.well-known/apple-app-site-association", appleAppSiteAssociationHandler)
	r.Get("/native/initiate", initiateNativeFlow)

	log.Println("Listening on :" + env.Getenv("PORT", port))
	log.Fatal(http.ListenAndServe(":"+env.Getenv("PORT", port), r))
}

/*
Request handlers
*/

func home(w http.ResponseWriter, r *http.Request) {

	loginSession, _ := r.Cookie(loginSessionName)

	renderTemplate(w, "home.html", map[string]interface{}{
		"ClientID":     oauth2Config().ClientID,
		"ClientSecret": oauth2Config().ClientSecret,
		"Users":        model.Store.FindAll(),
		"LoginSession": loginSession,
		"Action":       "/clients",
	})
}

// RPのOAuth2 Client情報を保存する
func saveClient(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("client_id")
	secret := r.FormValue("client_secret")

	if r.FormValue("submit") == "Reset" {
		id = os.Getenv("DEFAULT_CLIENT_ID")
		secret = os.Getenv("DEFAULT_CLIENT_SECRET")
	}

	loadOAuth2Config(id, secret)

	http.Redirect(w, r, "/", http.StatusFound)
}

// 認可リクエストを生成する
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

	reqSession, _ := store.Get(r, authZReqSessionName)

	// state - CSRF protection
	reqSession.Values["state"] = string(state)
	// nonce - replay attack protection
	reqSession.Values["nonce"] = string(nonce)
	// PKCE - 認可コード横取り対策
	codeVerifier, _ := randx.RuneSequence(64, randx.AlphaLower)
	converted := sha256.Sum256([]byte(string(codeVerifier)))
	codeChallenge := base64.RawURLEncoding.EncodeToString(converted[:])
	codeChallengeMethod := "S256"
	reqSession.Values["code_verifier"] = string(codeVerifier)

	reqSession.Save(r, w)

	authZReqWithPromptLoginURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"), // custom parameter
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
	)

	authZReqWithPromptRegistrationURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", "registration"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"), // custom parameter
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
	)

	authZReqWithPromptNoneURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", "none"),
		//oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"), // custom parameter
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
	)

	renderTemplate(w, "initiate.html", map[string]interface{}{
		"AuthZReqWithPromptLoginURL":        authZReqWithPromptLoginURL,
		"AuthZReqWithPromptRegistrationURL": authZReqWithPromptRegistrationURL,
		"AuthZReqWithPromptNoneURL":         authZReqWithPromptNoneURL,
	})

}

func initiateNativeFlow(w http.ResponseWriter, r *http.Request) {
	// TODO: state, nonce, PKCE
	conf := oauth2Config()
	state := "DUMMY"
	authZReqWithPromptLoginURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
	)

	authZReqWithPromptRegistrationURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("prompt", "registration"),
		oauth2.SetAuthURLParam("max_age", "0"),
	)

	w.Header().Set("Content-Type", "application/json")

	data := map[string]interface{}{
		"loginURL":        authZReqWithPromptLoginURL,
		"registrationURL": authZReqWithPromptRegistrationURL,
	}

	json.NewEncoder(w).Encode(data)
}

// 認可レスポンスを受け取る(redirect_uri)
func authzReqCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(r.URL.Query().Get("error")) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Got error: %s\n", r.URL.Query().Get("error_description"))

		w.WriteHeader(http.StatusInternalServerError)

		// TODO: error
		return
	}

	state := r.URL.Query().Get("state")
	fmt.Printf("state: %s\n", state)

	reqSession, _ := store.Get(r, authZReqSessionName)
	if reqSession.IsNew {
		fmt.Printf("session not found\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	stateInSession := reqSession.Values["state"].(string)

	if state != stateInSession {
		fmt.Printf("state not match\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	codeVerifier := reqSession.Values["code_verifier"].(string)

	code := r.URL.Query().Get("code")
	conf := oauth2Config()

	tokens, err := auth.TokenRequestWithPrivateKeyJwt(conf, code, codeVerifier)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Unable to exchange code for token: %s\n", err)

		w.WriteHeader(http.StatusInternalServerError)

		// TODO: error
		return
	}

	/*Example of ID Token
	{
	  "alg": "RS256",
	  "kid": "59806f55-8abb-48e4-9543-a168bc6264af",
	  "typ": "JWT"
	}
	{
	  "acr": "face_acr",
	  "at_hash": "1okgxnlVSurY_sNeU0FEGQ",
	  "aud": [
	    "8d14540d-55b7-4d55-8eaf-cf1392dbbcd9"
	  ],
	  "auth_time": 1722388130,
	  "baz": "bar",
	  "exp": 1722391735,
	  "family_name": "Doe",
	  "given_name": "John",
	  "iat": 1722388135,
	  "iss": "http://127.0.0.1:4444",
	  "jti": "bdf7fe59-fffa-4ba3-b8b1-f6cde3a00e63",
	  "nonce": "negokqonugcxnuqxzbcptsgc",
	  "phone_number": "08012345678",
	  "phone_number_verified": true,
	  "rat": 1722388128,
	  "sid": "1194bfd5-4496-4300-aa5f-9591db56dc38",
	  "sub": "d91d6630a562a8f3bd5d217eb39e05747e2a4b8369490cf02fcf6d325a10e609"
	}
	*/

	set, err := fetchJWKs(ctx)
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
	fmt.Printf("verifiedToken: %#v\n", verifiedToken)
	n, exist := verifiedToken.Get("nonce")
	if !exist {
		fmt.Printf("nonce not found\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	nonce, ok := n.(string)
	if !ok {
		fmt.Printf("nonce is not string\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	nonceInSession := reqSession.Values["nonce"].(string)
	if nonce != nonceInSession {
		fmt.Printf("nonce not match %s != %s", nonce, nonceInSession)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// 認可リクエストのセッションを削除
	reqSession.Options.MaxAge = -1
	reqSession.Save(r, w)

	s, exist := verifiedToken.Get("sid")
	if !exist {
		fmt.Printf("sid not found\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sid, ok := s.(string)
	if !ok {
		fmt.Printf("sd is not string\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// TODO: sidってsessionと紐づける必要あったっけ?
	_ = sid
	sub := verifiedToken.Subject()
	user := model.Store.FindOrCreateBySubject(&model.User{Subject: sub, IDToken: idTokenStr})

	// Login sessionの発行
	session, _ := store.Get(r, loginSessionName)
	session.Values["user_id"] = int(user.ID)
	if err = session.Save(r, w); err != nil {
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

// RP-initiated Logout
// SEE: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
func logout(w http.ResponseWriter, r *http.Request) {
	fmt.Print("[RP]==========================> logout called\n")
	query := r.URL.Query()
	id, _ := strconv.Atoi(query.Get("id"))

	usr, exist := model.Store.Find(model.ID(id))
	err := ""
	if !exist {
		err = "User not found"
	}

	_ = usr

	u := urlx.AppendPaths(&hydraAuthZReqURL, "/oauth2/sessions/logout")
	u = urlx.SetQuery(u, url.Values{
		// TODO: stateを付与
		"id_token_hint":            []string{usr.IDToken},
		"post_logout_redirect_uri": []string{"http://127.0.0.1:5555/logout_callback"},
		"client_id":                []string{oauth2Config().ClientID},
		//"client_id": []string{"i_am_invalid_client_id"},
	})
	renderTemplate(w, "logout.html", map[string]interface{}{
		"LogoutURL": u.String(),
		"Error":     err,
	})
}

// RP-initiated Logout Callback (post_logout_redirect_uri)
func logoutCallback(w http.ResponseWriter, r *http.Request) {
	fmt.Print("[RP]==========================> logoutCallback called\n")
	state := r.URL.Query().Get("state")
	fmt.Printf("state: %s\n", state)
	// TODO: Check state

	// TODO: AuthZ Request(prompt=none) to check OP session logged-out
	// http.Redirect(w, r, "{AuthZ Request URL}", http.StatusFound)

	session, _ := store.Get(r, loginSessionName)
	session.Options.MaxAge = -1
	session.Save(r, w)

	renderTemplate(w, "complete_logout.html", map[string]interface{}{})
}

func backchannelLogout(w http.ResponseWriter, r *http.Request) {
	fmt.Print("[RP]==========================> backchannelLogout called\n")
	ctx := r.Context()
	r.ParseForm()

	logoutToken := r.FormValue("logout_token")

	fmt.Printf("logout_token: %s\n", logoutToken)
	/*Example of Logout Token
	{
	  "alg": "RS256",
	  "kid": "59806f55-8abb-48e4-9543-a168bc6264af",
	  "typ": "JWT"
	}
	{
	  "aud": [
	    "8d14540d-55b7-4d55-8eaf-cf1392dbbcd9"
	  ],
	  "events": {
	    "http://schemas.openid.net/event/backchannel-logout": {}
	  },
	  "iat": 1722390423,
	  "iss": "http://127.0.0.1:4444",
	  "jti": "1a98ab41-f8f6-4ade-93c0-4aec62114e08",
	  "sid": "955e98f4-a313-4c7f-9057-ed3435bd96ad"
	}
	*/
	set, err := fetchJWKs(ctx)
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
	fmt.Printf("verifiedToken: %#v\n", verifiedToken)
	s, exist := verifiedToken.Get("sid")
	if !exist {
		fmt.Printf("sid not found\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sid, ok := s.(string)
	if !ok {
		fmt.Printf("sd is not string\n")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Printf("backchannelLogout > sid: %s\n", sid)

	// SEE: https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
	// GET session by sid
	// DELETE session by sid
	// Delete Refresh Token issued without offline_access

	w.WriteHeader(http.StatusOK)
}

// GET /.well-known/jwks.json
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("/.well-known/jwks.json accessed\n")

	w.Header().Set("Content-Type", "application/json")
	file, err := os.Open("keys/public_key.jwk")
	if err != nil {
		fmt.Printf("failed to open JWK file: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer file.Close()

	var jwkData map[string]interface{}
	if err := json.NewDecoder(file).Decode(&jwkData); err != nil {
		fmt.Printf("failed to decode JWK file: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{jwkData}})
}

// GET /.well-known/apple-app-site-association
func appleAppSiteAssociationHandler(w http.ResponseWriter, r *http.Request) {
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

/*
	Internal functions
*/

func fetchJWKs(ctx context.Context) (jwk.Set, error) {
	return jwk.Fetch(
		ctx,
		"http://hydra:4444/.well-known/jwks.json",
	)
}

func oauth2Config() oauth2.Config {
	return oauth2Conf
}

func loadOAuth2Config(id, secret string) {
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
