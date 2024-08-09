package main

import (
	"fmt"
	"html/template"
	"io"
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

	fmt.Printf("[IdP]============> hydraAdminURL: %s\n", hydraAdminURL)
}

func main() {
	r := chi.NewRouter()

	r.Get("/", home)
	r.Get("/register", getRegisterPage)
	r.Post("/register", register)
	r.Get("/login", getLoginPage)
	r.Post("/login", login)
	r.Get("/consent", getConsentPage)
	r.Post("/consent", consent)
	r.Get("/logout", getLogoutPage)
	r.Post("/logout", logout)

	r.Post("/refresh_token_hook", tokenHook)
	r.Post("/token_hook", tokenHook)

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

// ユーザー登録画面表示( GET /register )
func getRegisterPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	challenge := query.Get("login_challenge")
	if challenge == "" {
		http.Error(w, "Expected a login challenge to be set but received none.", http.StatusBadRequest)
		return
	}
	hydraClient := hydraClient()

	respGetLoginReq, _, err := hydraClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch login request: %v", err), http.StatusInternalServerError)
		return
	}

	_ = respGetLoginReq

	csrfToken := csrf.Token(r)
	registerURL := url.URL{
		Scheme: "http",
		Host:   r.Host,
		Path:   "/register",
	}

	renderTemplate(w, "register.html", map[string]interface{}{
		"Challenge": challenge,
		"CSRFToken": csrfToken,
		"Action":    registerURL.String(),
	})
}

// ユーザー登録処理( POST /register )
func register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
		respRejectLoginReq, _, err := hydraClient.OAuth2API.RejectOAuth2LoginRequest(ctx).LoginChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
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

	// TODO: Save User
	_, _ = password, email

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
	hydraReq.IdentityProviderSessionId = pointer("hoge")
	// remember trueにすると、このあとの認可リクエストでory_hydra_session_dev セッションがSet-Cookieされる
	hydraReq.Remember = pointer(true)
	rememberFor := int64(3600)
	hydraReq.RememberFor = &rememberFor
	hydraReq.Acr = pointer("fack_acr")

	respAcceptLoginReq, _, err := hydraClient.OAuth2API.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to accept login request: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, respAcceptLoginReq.RedirectTo, http.StatusFound)
}

// ログイン画面表示( GET /login )
func getLoginPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	challenge := query.Get("login_challenge")
	if challenge == "" {
		http.Error(w, "Expected a login challenge to be set but received none.", http.StatusBadRequest)
		return
	}

	hydraClient := hydraClient()

	respGetLoginReq, _, err := hydraClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch login request: %v", err), http.StatusInternalServerError)
		return
	}

	// Check if login can be skipped
	if respGetLoginReq.Skip {
		hydraReq := hydra.NewAcceptOAuth2LoginRequest(respGetLoginReq.Subject)
		respAcceptLoginReq, _, err := hydraClient.OAuth2API.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
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
		"Action":    loginURL.String(),
		"Hint":      hint,
	})
}

// ログイン処理( POST /login )
func login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
		respRejectLoginReq, _, err := hydraClient.OAuth2API.RejectOAuth2LoginRequest(ctx).LoginChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
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
	hydraReq.IdentityProviderSessionId = pointer("hoge")
	// remember trueにすると、このあとの認可リクエストでory_hydra_session_dev セッションがSet-Cookieされる
	hydraReq.Remember = pointer(r.FormValue("remember") == "true")
	rememberFor := int64(3600)
	hydraReq.RememberFor = &rememberFor
	hydraReq.Acr = pointer("fack_acr")

	respAcceptLoginReq, _, err := hydraClient.OAuth2API.AcceptOAuth2LoginRequest(ctx).LoginChallenge(challenge).AcceptOAuth2LoginRequest(*hydraReq).Execute()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to accept login request: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, respAcceptLoginReq.RedirectTo, http.StatusFound)
}

// 同意画面表示( GET /consent )
func getConsentPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	challenge := query.Get("consent_challenge")
	if challenge == "" {
		http.Error(w, "Expected a consent challenge to be set but received none.", http.StatusBadRequest)
		return
	}

	hydraClient := hydraClient()

	consentRequest, _, err := hydraClient.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, "Failed to fetch consent request information", http.StatusInternalServerError)
		return
	}

	// consentRequest.Skip は End-User がスキップ選択したとき(Remember=true)にtrueになる
	// consent.Client.SkipConsentは Client設定でスキップ設定されている場合にtrueになる
	skipConsent := false
	if consentRequest.Skip != nil {
		skipConsent = *consentRequest.Skip
	} else if consentRequest.Client.SkipConsent != nil {
		skipConsent = *consentRequest.Client.SkipConsent
	}

	if skipConsent {
		rememberFor := int64(3600)
		body, _, err := hydraClient.OAuth2API.AcceptOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{
			Context:                  map[string]interface{}{"foo": "bar"},
			GrantScope:               consentRequest.GetRequestedScope(),
			Session:                  nil,
			GrantAccessTokenAudience: consentRequest.RequestedAccessTokenAudience,
			Remember:                 pointer(true),
			RememberFor:              &rememberFor,
		}).Execute()
		if err != nil {
			http.Error(w, "Failed to accept consent request", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, body.RedirectTo, http.StatusFound)
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

// 同意処理( POST /consent )
func consent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	challenge := r.FormValue("challenge")

	hydraClient := hydraClient()

	// Let's see if the user decided to accept or reject the consent request..
	if r.FormValue("submit") == "Deny access" {
		// Looks like the consent request was denied by the user
		hydraReq := hydra.NewRejectOAuth2Request()
		hydraReq.Error = pointer("access_denied")
		hydraReq.ErrorDescription = pointer("The resource owner denied the request")
		body, _, err := hydraClient.OAuth2API.RejectOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).RejectOAuth2Request(*hydraReq).Execute()
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

	consentRequest, _, err := hydraClient.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, "Failed to fetch consent request information", http.StatusInternalServerError)
		return
	}

	// client.metadata(JSON) に独自データを詰め込めるので、その値を参照して処理分岐させることができる
	clientMeta := consentRequest.Client.GetMetadata()
	rawUserID := clientMeta["raw_user_id"]
	includeRawUserID := false
	if rawUserID != nil {
		includeRawUserID = rawUserID.(bool)
	}

	// NOTE: DBのhydra_oauth2_flow.(session_access_token|session_id_token) にそれぞれ保存される
	// session.IdTokenのclaimsはID TokenのpayloadにもUserinfo Responseにも含まれる
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
			"ext": map[string]interface{}{
				"hoge": "fuga",
				"piyo": []string{"a", "b", "c"},
			},
		},
	}
	if includeRawUserID {
		session.SetIdToken(
			map[string]interface{}{
				"baz":                   "bar",
				"phone_number":          "08012345678",
				"phone_number_verified": true,
				"family_name":           "Doe",
				"given_name":            "John",
				"ext": map[string]interface{}{
					"hoge": "fuga",
					"piyo": []string{"a", "b", "c"},
				},
				"raw_user_id": "1234567890", // たとえば、DBのraw ID を突っ込むとか
			},
		)
	}

	remember, _ := strconv.ParseBool(r.FormValue("remember"))
	rememberFor := int64(3600)
	body, _, err := hydraClient.OAuth2API.AcceptOAuth2ConsentRequest(ctx).ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(hydra.AcceptOAuth2ConsentRequest{
		Context:                  map[string]interface{}{"foo": "bar"},
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

// ログアウト画面表示( GET /logout )
func getLogoutPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	challenge := r.URL.Query().Get("logout_challenge")
	if challenge == "" {
		http.Error(w, "expected a logout challenge to be set but received none", http.StatusBadRequest)
		return
	}

	hydraClient := hydraClient()

	_, _, err := hydraClient.OAuth2API.GetOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	csrfToken := csrf.Token(r)
	renderTemplate(w, "logout.html", map[string]interface{}{
		"Action":    "/logout",
		"Challenge": challenge,
		"CsrfToken": csrfToken,
	})

}

// ログアウト処理( POST /logout )
func logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	challenge := r.FormValue("challenge")
	if challenge == "" {
		http.Error(w, "expected a logout challenge to be set but received none", http.StatusBadRequest)
		return
	}

	hydraClient := hydraClient()

	action := r.FormValue("submit")
	if action == "No" {
		_, err := hydraClient.OAuth2API.RejectOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "https://www.ory.sh/", http.StatusSeeOther)
		return
	}

	// ユーザーがログアウトに同意した場合
	resp, _, err := hydraClient.OAuth2API.AcceptOAuth2LogoutRequest(ctx).LogoutChallenge(challenge).Execute()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Redirecting to: %s", resp.RedirectTo)
	http.Redirect(w, r, resp.RedirectTo, http.StatusSeeOther)
}

// トークンHook( POST /token_hook )
func tokenHook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path := r.URL.Path

	fmt.Printf("[IdP / Token Hook / %s] ======> Received JSON: %s\n", path, string(body))

	w.WriteHeader(http.StatusNoContent)
}

/*
Internal functions
*/
func hydraClient() *hydra.APIClient {
	client := hydra.NewConfiguration()
	client.Servers = hydra.ServerConfigurations{{URL: hydraAdminURL}}
	return hydra.NewAPIClient(client)
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
