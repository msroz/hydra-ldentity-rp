package controllers

import (
	"fmt"
	"idp/model"
	"idp/view"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

type AuthController struct {
	store        *sessions.CookieStore
	hydraService *model.HydraService
	tmplService  *view.TemplateService
}

func NewAuthController(store *sessions.CookieStore, hydraService *model.HydraService, tmplService *view.TemplateService) *AuthController {
	return &AuthController{
		store:        store,
		hydraService: hydraService,
		tmplService:  tmplService,
	}
}

func (c *AuthController) LoginForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	challenge := query.Get("login_challenge")
	if challenge == "" {
		errorMsg := url.QueryEscape("Expected a login challenge to be set but received none.")
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	hint := query.Get("hint")

	respGetLoginReq, err := c.hydraService.GetLoginRequest(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to fetch login request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	if respGetLoginReq.Skip {
		redirectTo, err := c.hydraService.AcceptLogin(ctx, challenge, respGetLoginReq.Subject)
		if err != nil {
			errorMsg := url.QueryEscape(fmt.Sprintf("Failed to accept login request: %v", err))
			http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	parsedUrl, _ := url.Parse(respGetLoginReq.GetRequestUrl())
	params := parsedUrl.Query()

	viaRegister := false
	if value, ok := params["prompt"]; ok && value[0] == "registration" {
		viaRegister = true
	}

	action := url.URL{
		Scheme: "http",
		Host:   r.Host,
		Path:   "/login",
	}

	if respGetLoginReq.OidcContext != nil && respGetLoginReq.OidcContext.LoginHint != nil {
		hint = *respGetLoginReq.OidcContext.LoginHint
	}

	c.tmplService.RenderTemplate(w, "login.html", map[string]interface{}{
		"Challenge":      challenge,
		csrf.TemplateTag: csrf.TemplateField(r),
		"Action":         action.String(),
		"Hint":           hint,
		"ViaRegister":    viaRegister,
	})
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	challenge := r.FormValue("challenge")
	if challenge == "" {
		errorMsg := url.QueryEscape("Expected a login challenge to be set but received none.")
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	if r.FormValue("submit") == "Deny access" {
		redirectTo, err := c.hydraService.RejectLogin(ctx, challenge)
		if err != nil {
			errorMsg := url.QueryEscape(fmt.Sprintf("Failed to reject login request: %v", err))
			http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	loginID := r.FormValue("login_id")
	user, ok := model.Store.FindByLoginID(loginID)

	if !ok {
		http.Redirect(w, r, "/login?challenge="+challenge, http.StatusSeeOther)
		return
	}

	session, _ := c.store.Get(r, "identity_login_session")
	session.Values["user_id"] = int(user.ID)
	if err := session.Save(r, w); err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to save session: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	redirectTo, err := c.hydraService.AcceptLoginWithSession(ctx, challenge, loginID, session.ID)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to accept login request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (c *AuthController) ConsentForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	challenge := query.Get("consent_challenge")
	if challenge == "" {
		errorMsg := url.QueryEscape("Expected a consent challenge to be set but received none.")
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	consentRequest, err := c.hydraService.GetConsentRequest(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to fetch consent request information: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	skipConsent := false
	if consentRequest.Skip != nil {
		skipConsent = *consentRequest.Skip
	}
	if consentRequest.Client.SkipConsent != nil {
		skipConsent = *consentRequest.Client.SkipConsent
	}

	if skipConsent {
		redirectTo, err := c.hydraService.AcceptConsent(ctx, challenge, consentRequest.GetRequestedScope(), consentRequest.RequestedAccessTokenAudience)
		if err != nil {
			errorMsg := url.QueryEscape(fmt.Sprintf("Failed to accept consent request: %v", err))
			http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	c.tmplService.RenderTemplate(w, "consent.html", map[string]interface{}{
		"Action":         "/consent",
		"Challenge":      challenge,
		csrf.TemplateTag: csrf.TemplateField(r),
		"Client":         consentRequest.Client,
		"RequestedScope": consentRequest.RequestedScope,
		"User":           consentRequest.Subject,
	})
}

func (c *AuthController) Consent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()
	challenge := r.FormValue("challenge")

	if r.FormValue("submit") == "Deny access" {
		redirectTo, err := c.hydraService.RejectConsent(ctx, challenge)
		if err != nil {
			errorMsg := url.QueryEscape(fmt.Sprintf("Failed to reject consent request: %v", err))
			http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	grantScope := r.Form["grant_scope"]
	if len(grantScope) == 0 {
		grantScope = []string{r.FormValue("grant_scope")}
	}

	consentRequest, err := c.hydraService.GetConsentRequest(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to fetch consent request information: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	clientMeta := consentRequest.Client.GetMetadata()
	rawUserID := clientMeta["raw_user_id"]
	includeRawUserID := false
	if rawUserID != nil {
		includeRawUserID = rawUserID.(bool)
	}

	session := c.hydraService.CreateConsentSession(includeRawUserID)
	remember, _ := strconv.ParseBool(r.FormValue("remember"))

	redirectTo, err := c.hydraService.AcceptConsentWithSession(ctx, challenge, grantScope, consentRequest.RequestedAccessTokenAudience, session, remember)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to accept consent request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (c *AuthController) LogoutForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	challenge := r.URL.Query().Get("logout_challenge")
	if challenge == "" {
		errorMsg := url.QueryEscape("expected a logout challenge to be set but received none")
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	_, err := c.hydraService.GetLogoutRequest(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to fetch logout request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	c.tmplService.RenderTemplate(w, "logout.html", map[string]interface{}{
		"Action":         "/logout",
		"Challenge":      challenge,
		csrf.TemplateTag: csrf.TemplateField(r),
	})
}

func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	challenge := r.FormValue("challenge")
	if challenge == "" {
		errorMsg := url.QueryEscape("expected a logout challenge to be set but received none")
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	action := r.FormValue("submit")
	if action == "No" {
		err := c.hydraService.RejectLogout(ctx, challenge)
		if err != nil {
			errorMsg := url.QueryEscape(fmt.Sprintf("Failed to reject logout request: %v", err))
			http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "https://www.ory.sh/", http.StatusSeeOther)
		return
	}

	redirectTo, err := c.hydraService.AcceptLogout(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to accept logout request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

func (c *AuthController) PostLogout(w http.ResponseWriter, r *http.Request) {
	fmt.Print("[Identity]==========================> postLogout called\n")
}

func (c *AuthController) TokenHook(w http.ResponseWriter, r *http.Request) {
	c.hydraService.HandleTokenHook(w, r)
}
