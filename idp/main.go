package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	hydra "github.com/ory/client-go"
	"github.com/ory/common/env"
	"github.com/pkg/errors"
)

const (
	port = "3000"
)

var (
	hydraAdminURL string
)

func init() {
	hydraAdminURL = os.Getenv("HYDRA_ADMIN_URL")
	if hydraAdminURL == "" {
		log.Fatal("HYDRA_ADMIN_URL environment variable not set")
	}

	fmt.Printf("[RP]============> hydraAdminURL: %s\n", hydraAdminURL)
}

func main() {
	r := chi.NewRouter()

	r.Get("/", home)
	r.Get("/login", getLoginPage)
	r.Post("/login", login)
	r.Get("/consent", getConsentPage)
	r.Post("/consent", consent)

	log.Println("Listening on :" + env.Getenv("PORT", port))
	log.Fatal(http.ListenAndServe(":"+env.Getenv("PORT", port), r))
}

/*
	Request handlers
*/

func home(w http.ResponseWriter, r *http.Request) {

	opSession, err := r.Cookie("ory_hydra_session_dev")
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	loginURL := url.URL{
		Scheme: "http",
		Host:   r.Host,
		Path:   "/login",
	}
	renderTemplate(w, "home.html", map[string]interface{}{
		"LoginURL": loginURL.String(),
		"Error":    errMsg,
		"Session":  opSession,
	})
}

func getLoginPage(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	challenge := query.Get("login_challenge")
	if challenge == "" {
		http.Error(w, "Expected a login challenge to be set but received none.", http.StatusBadRequest)
		return
	}

	hydraClient := hydraClient()

	respGetLoginReq, _, err := hydraClient.OAuth2API.GetOAuth2LoginRequest(r.Context()).LoginChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch login request: %v", err), http.StatusInternalServerError)
		return
	}

	// Check if login can be skipped
	if respGetLoginReq.Skip {
		hydraReq := hydra.NewAcceptOAuth2LoginRequest(respGetLoginReq.Subject)
		respAcceptLoginReq, _, err := hydraClient.OAuth2API.AcceptOAuth2LoginRequest(r.Context()).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to accept login request: %v", err), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, respAcceptLoginReq.RedirectTo, http.StatusFound)
		return
	}

	csrfToken := csrf.Token(r)
	loginURL := url.URL{
		Scheme: "http",
		Host:   r.Host,
		Path:   "/login",
	}

	hint := ""
	if respGetLoginReq.OidcContext != nil && respGetLoginReq.OidcContext.LoginHint != nil {
		hint = *respGetLoginReq.OidcContext.LoginHint
	}

	renderTemplate(w, "login.html", map[string]interface{}{
		"Challenge": challenge,
		"CSRFToken": csrfToken,
		"LoginURL":  loginURL.String(),
		"Hint":      hint,
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	challenge := r.FormValue("challenge")
	if challenge == "" {
		http.Error(w, "Expected a login challenge to be set but received none.", http.StatusBadRequest)
		return
	}
	// TODO: check CsrfToken

	hydraClient := hydraClient()

	// Check if the user decided to accept or reject the consent request
	if r.FormValue("submit") == "Deny access" {
		hydraReq := hydra.NewRejectOAuth2Request()
		respRejectLoginReq, _, err := hydraClient.OAuth2API.RejectOAuth2LoginRequest(r.Context()).LoginChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to reject login request: %v", err), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, respRejectLoginReq.RedirectTo, http.StatusFound)
		return
	}

	// Validate user credentials (dummy check for example)
	email := r.FormValue("email")
	password := r.FormValue("password")
	if email != "foo@bar.com" || password != "foobar" {
		csrfToken := csrf.Token(r)
		loginURL := url.URL{
			Scheme: "http",
			Host:   r.Host,
			Path:   "/login",
		}
		hint := ""
		renderTemplate(w, "login.html", map[string]interface{}{
			"Challenge": challenge,
			"CsrfToken": csrfToken,
			"LoginURL":  loginURL.String(),
			"Hint":      hint,
			"Error":     "The username / password combination is not correct",
		})
		return
	}

	// TODO: Issue login session (hydra sessionとの棲み分け?)

	/*
		_, _, err := hydraClient.OAuth2API.GetOAuth2LoginRequest(r.Context()).LoginChallenge(challenge).Execute()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch login request: %v", err), http.StatusInternalServerError)
			return
		}
	*/

	// User authenticated, accept the login request
	hydraReq := hydra.NewAcceptOAuth2LoginRequest(email) // email is the subject
	// remember trueにすると、このあとの認可リクエストでory_hydra_session_dev セッションがSet-Cookieされる
	hydraReq.Remember = pointer(r.FormValue("remember") == "true")
	rememberFor := int64(3600)
	hydraReq.RememberFor = &rememberFor
	hydraReq.Acr = pointer("face_acr")

	respAcceptLoginReq, _, err := hydraClient.OAuth2API.AcceptOAuth2LoginRequest(r.Context()).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to accept login request: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, respAcceptLoginReq.RedirectTo, http.StatusFound)
}

func getConsentPage(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	challenge := query.Get("consent_challenge")
	if challenge == "" {
		http.Error(w, "Expected a consent challenge to be set but received none.", http.StatusBadRequest)
		return
	}

	hydraClient := hydraClient()

	// Fetch consent request information from ORY Hydra
	consentRequest, _, err := hydraClient.OAuth2API.GetOAuth2ConsentRequest(r.Context()).ConsentChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, "Failed to fetch consent request information", http.StatusInternalServerError)
		return
	}

	// If consent can be skipped
	if consentRequest.Skip != nil && *consentRequest.Skip {
		// TODO:
		http.Error(w, "TODO: acceptOAuth2Consent because of skip consent", http.StatusInternalServerError)
		return
	}

	// If consent can't be skipped, show the consent UI
	csrfToken := csrf.Token(r)
	renderTemplate(w, "consent.html", map[string]interface{}{
		"Action":         "/consent",
		"Challenge":      challenge,
		"CsrfToken":      csrfToken,
		"Client":         consentRequest.Client,
		"RequestedScope": consentRequest.RequestedScope,
		"User":           consentRequest.Subject,
	})
}

func consent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	challenge := r.FormValue("challenge")

	hydraClient := hydraClient()

	// Let's see if the user decided to accept or reject the consent request..
	if r.FormValue("submit") == "Deny access" {
		// Looks like the consent request was denied by the user
		hydraReq := hydra.NewRejectOAuth2Request()
		hydraReq.Error = pointer("access_denied")
		hydraReq.ErrorDescription = pointer("The resource owner denied the request")
		body, _, err := hydraClient.OAuth2API.RejectOAuth2ConsentRequest(r.Context()).ConsentChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
		if err != nil {
			http.Error(w, "Failed to reject consent request", http.StatusInternalServerError)
			return
		}

		// All we need to do now is to redirect the browser back to hydra!
		http.Redirect(w, r, body.RedirectTo, http.StatusFound)
		return
	}

	grantScope := r.Form["grant_scope"]
	if len(grantScope) == 0 {
		grantScope = []string{r.FormValue("grant_scope")}
	}

	// The session allows us to set session data for id and access tokens
	// NOTE: DBのhydra_oauth2_flow.(session_access_token|session_id_token) にそれぞれ保存される
	// session.IdTokenのclaimsはID Tokenのpayloadにも含まれる
	/*
		$ curlie -X GET -H "Authorization: Bearer ory_at_fHInGUwUOWxZyHtzxnSJd8tKbYSNNTEZoRMwma2_FlI.Dr_eB53DT0PSMx7ki3dVmyvNlU2fLmRAp3KSy_JsQcE" http://localhost:4444/userinfo
		HTTP/1.1 200 OK
		Cache-Control: private, no-cache, no-store, must-revalidate
		Content-Type: application/json; charset=utf-8
		Date: Thu, 25 Jul 2024 06:45:16 GMT
		Content-Length: 336

		{
		    "acr": "face_acr",
		    "aud": [
		        "89657dc9-8dbc-4c4b-9d7f-e7fac531fb8e"
		    ],
		    "auth_time": 1721888706,
		    "baz": "bar",
		    "family_name": "Doe",
		    "given_name": "John",
		    "iat": 1721888711,
		    "iss": "http://127.0.0.1:4444",
		    "phone_number": "08012345678",
		    "phone_number_verified": true,
		    "rat": 1721888701,
		    "sub": "d91d6630a562a8f3bd5d217eb39e05747e2a4b8369490cf02fcf6d325a10e609"
		}
	*/
	session := hydra.AcceptOAuth2ConsentRequestSession{
		AccessToken: map[string]interface{}{
			"foo": "bar",
		},
		IdToken: map[string]interface{}{
			"baz":                   "bar",
			"phone_number":          "08012345678",
			"phone_number_verified": true,
			"family_name":           "Doe",
			"given_name":            "John",
		},
	}

	// Let's fetch the consent request again to be able to set `grantAccessTokenAudience` properly.
	consentRequest, _, err := hydraClient.OAuth2API.GetOAuth2ConsentRequest(r.Context()).ConsentChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, "Failed to fetch consent request information", http.StatusInternalServerError)
		return
	}

	remember, _ := strconv.ParseBool(r.FormValue("remember"))
	rememberFor := int64(3600)
	body, _, err := hydraClient.OAuth2API.AcceptOAuth2ConsentRequest(r.Context()).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{
		GrantScope:               grantScope,
		Session:                  &session,
		GrantAccessTokenAudience: consentRequest.RequestedAccessTokenAudience,
		Remember:                 pointer(remember),
		RememberFor:              &rememberFor,
	}).Execute()
	if err != nil {
		http.Error(w, "Failed to accept consent request", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, body.RedirectTo, http.StatusFound)
}

func hydraClient() *hydra.APIClient {
	client := hydra.NewConfiguration()
	client.Servers = hydra.ServerConfigurations{{URL: hydraAdminURL}}
	return hydra.NewAPIClient(client)
}

/*
	Internal functions
*/

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
