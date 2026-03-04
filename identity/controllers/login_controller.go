package controllers

import (
	"fmt"
	"idp/model"
	"idp/view"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

const identityLoginSessionName = "identity_login_session"

type LoginController struct {
	store        *sessions.CookieStore
	hydraService *model.HydraService
	tmplService  *view.TemplateService
}

func NewLoginController(store *sessions.CookieStore, hydraService *model.HydraService, tmplService *view.TemplateService) *LoginController {
	return &LoginController{
		store:        store,
		hydraService: hydraService,
		tmplService:  tmplService,
	}
}

func (c *LoginController) LoginForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	challenge := query.Get("login_challenge")
	if challenge == "" {
		errorMsg := url.QueryEscape("Expected a login challenge to be set but received none.")
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	loginReq, err := c.hydraService.GetLoginRequest(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to fetch login request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	session, _ := c.store.Get(r, identityLoginSessionName)
	currentUser, _ := model.Store.FindBySessionValue(session.Values["user_id"])

	slog.Debug("LoginForm", "skip", loginReq.Skip)
	if loginReq.Skip {
		if currentUser != nil && currentUser.LoginID == loginReq.Subject {
			redirectTo, err := c.hydraService.AcceptLogin(ctx, challenge, loginReq.Subject)
			if err != nil {
				errorMsg := url.QueryEscape(fmt.Sprintf("Failed to accept login request: %v", err))
				http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}

		// TODO: prompt=noneの場合は、Rejectしてlogin_requiredを返すのが妥当。
	}

	parsedUrl, _ := url.Parse(loginReq.GetRequestUrl())
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

	slog.Debug("LoginForm", "loginReq.OidcContext", loginReq.OidcContext)
	if loginReq.OidcContext != nil {
		logIdTokenHintDiagnostics(loginReq.OidcContext.GetIdTokenHintClaims(), currentUser)
	}

	hint := ""
	if loginReq.OidcContext != nil && loginReq.OidcContext.LoginHint != nil {
		hint = *loginReq.OidcContext.LoginHint
	}

	c.tmplService.RenderTemplate(w, "login.html", map[string]interface{}{
		"Challenge":      challenge,
		csrf.TemplateTag: csrf.TemplateField(r),
		"Action":         action.String(),
		"Hint":           hint,
		"ViaRegister":    viaRegister,
		"LoggedInUser": currentUser,
	})
}

func (c *LoginController) Login(w http.ResponseWriter, r *http.Request) {
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

	session, _ := c.store.Get(r, identityLoginSessionName)
	session.Values["user_id"] = fmt.Sprintf("%d", user.ID)
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

func logIdTokenHintDiagnostics(claims map[string]interface{}, currentUser *model.User) {
	if len(claims) == 0 {
		return
	}

	if iatFloat, ok := claims["iat"].(float64); ok {
		iat := time.Unix(int64(iatFloat), 0)
		if elapsed := time.Since(iat); elapsed > 30*time.Second {
			slog.Info("id_token_hint iat is stale", "iat", iat.Format(time.RFC3339), "elapsed", elapsed.Round(time.Second))
		}
	}

	if sub, ok := claims["sub"].(string); ok && currentUser != nil && sub == currentUser.LoginID {
		slog.Info("id_token_hint sub matches OP session", "sub", sub, "login_id", currentUser.LoginID)
	}
}
