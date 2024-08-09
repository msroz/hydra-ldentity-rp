package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
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
	port = "5555"
)

var (
	clientID     string
	clientSecret string

	hydraAuthZReqURL url.URL = url.URL{Scheme: "http", Host: "127.0.0.1:4444"} // from RP UA to Hydra
	hydraTokenReqURL url.URL = url.URL{Scheme: "http", Host: "hydra:4444"}     // from RP Server to Hydra

	redirectURL string = fmt.Sprintf("http://127.0.0.1:%s/callback", port)
)

type User struct {
	ID      int
	IDToken string
}

type UserStore struct {
	sync.Mutex
	users  map[int]*User
	nextID int
}

var userStore = &UserStore{
	users:  map[int]*User{},
	nextID: 1,
}

func (us *UserStore) Create(u *User) int {
	us.Lock()
	defer us.Unlock()

	u.ID = us.nextID
	us.nextID++
	us.users[u.ID] = u
	return u.ID
}

func (us *UserStore) GetAll() []*User {
	us.Lock()
	defer us.Unlock()
	users := make([]*User, 0, len(us.users))
	for _, user := range us.users {
		users = append(users, user)
	}
	return users
}

func (us *UserStore) Get(id int) (*User, bool) {
	us.Lock()
	defer us.Unlock()
	user, exists := us.users[id]
	return user, exists
}

func (us *UserStore) Delete(id int) bool {
	us.Lock()
	defer us.Unlock()
	_, exists := us.users[id]
	if exists {
		delete(us.users, id)
	}
	return exists
}

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
	r.Get("/callback", authzReqCallback)
	r.Get("/logout", logout)
	r.Get("/logout_callback", logoutCallback)
	r.Post("/backchannel_logout", backchannelLogout)

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
		"Users":        userStore.GetAll(),
	})
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

	// TODO: state, nonceをsessionと紐づける
	// TODO: PKCE対応
	//   code_verifier, code_challenge, code_challenge_method を生成
	//   認可Requestにcode_challengeとcode_challenge_methodを追加

	authZReqWithPromptLoginURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"), // custom parameter
	)

	authZReqWithPromptRegistrationURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", "registration"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"), // custom parameter
	)

	authZReqWithPromptNoneURL := conf.AuthCodeURL(
		string(state),
		oauth2.SetAuthURLParam("audience", ""),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", "none"),
		//oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.SetAuthURLParam("rp", "hydra-identity-provider"), // custom parameter
	)

	renderTemplate(w, "initiate.html", map[string]interface{}{
		"AuthZReqWithPromptLoginURL":        authZReqWithPromptLoginURL,
		"AuthZReqWithPromptRegistrationURL": authZReqWithPromptRegistrationURL,
		"AuthZReqWithPromptNoneURL":         authZReqWithPromptNoneURL,
	})

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
	// TODO: Check state

	code := r.URL.Query().Get("code")
	conf := oauth2Config()
	// TODO: code_verifierをToken Requestに追加
	tokens, err := conf.Exchange(r.Context(), code)
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
	idTokenStr := fmt.Sprintf("%s", tokens.Extra("id_token"))

	set, err := fetchJWKs(ctx)
	if err != nil {
		fmt.Printf("failed to fetch JWKS: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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

	// TODO: Check nonce
	_ = nonce

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
	_ = sub

	idTokenPayload, _ := json.MarshalIndent(verifiedToken, "", "  ")

	userStore.Create(&User{IDToken: idTokenStr})

	renderTemplate(w, "callback.html", map[string]interface{}{
		"AccessToken":    tokens.AccessToken,
		"RefreshToken":   tokens.RefreshToken,
		"Expiry":         tokens.Expiry.Format(time.RFC1123),
		"IDToken":        idTokenStr,
		"IDTokenPayload": string(idTokenPayload),
	})

}

// RP-initiated Logout
// SEE: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
func logout(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	id, _ := strconv.Atoi(query.Get("id"))

	usr, exist := userStore.Get(id)
	err := ""
	if !exist {
		err = "User not found"
	}

	u := urlx.AppendPaths(&hydraAuthZReqURL, "/oauth2/sessions/logout")
	u = urlx.SetQuery(u, url.Values{
		// TODO: stateを付与
		"id_token_hint":            []string{usr.IDToken},
		"post_logout_redirect_uri": []string{"http://127.0.0.1:5555/logout_callback"},
	})
	renderTemplate(w, "logout.html", map[string]interface{}{
		"LogoutURL": u.String(),
		"Error":     err,
	})
}

// RP-initiated Logout Callback (post_logout_redirect_uri)
func logoutCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	fmt.Printf("state: %s\n", state)
	// TODO: Check state

	// TODO: AuthZ Request(prompt=none) to check OP session logged-out
	// http.Redirect(w, r, "{AuthZ Request URL}", http.StatusFound)

	http.Redirect(w, r, "/", http.StatusFound)
}

func backchannelLogout(w http.ResponseWriter, r *http.Request) {
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
