package controllers

import (
	"fmt"
	"idp/model"
	"idp/view"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

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

	hint := query.Get("hint")

	respGetLoginReq, err := c.hydraService.GetLoginRequest(ctx, challenge)
	if err != nil {
		errorMsg := url.QueryEscape(fmt.Sprintf("Failed to fetch login request: %v", err))
		http.Redirect(w, r, "/error?detail="+errorMsg, http.StatusSeeOther)
		return
	}

	loggedInUserID := ""
	session, _ := c.store.Get(r, "identity_login_session")
	if session != nil && session.Values["user_id"] != nil {
		loggedInUserID = session.Values["user_id"].(string)
	}

	slog.Debug("LoginForm", "skip", respGetLoginReq.Skip)
	if respGetLoginReq.Skip {
		if loggedInUserID != "" && loggedInUserID == respGetLoginReq.Subject {
			redirectTo, err := c.hydraService.AcceptLogin(ctx, challenge, respGetLoginReq.Subject)
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

	session, _ := c.store.Get(r, "identity_login_session")
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
