package controllers

import (
	"fmt"
	"idp/model"
	"idp/view"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gorilla/csrf"
)

type LogoutController struct {
	hydraService *model.HydraService
	tmplService  *view.TemplateService
}

func NewLogoutController(hydraService *model.HydraService, tmplService *view.TemplateService) *LogoutController {
	return &LogoutController{
		hydraService: hydraService,
		tmplService:  tmplService,
	}
}

func (c *LogoutController) LogoutForm(w http.ResponseWriter, r *http.Request) {
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

func (c *LogoutController) Logout(w http.ResponseWriter, r *http.Request) {
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

func (c *LogoutController) PostLogout(w http.ResponseWriter, r *http.Request) {
	slog.Info("postLogout called")
}
