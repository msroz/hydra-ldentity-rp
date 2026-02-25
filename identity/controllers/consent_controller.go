package controllers

import (
	"fmt"
	"idp/model"
	"idp/view"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/csrf"
)

type ConsentController struct {
	hydraService *model.HydraService
	tmplService  *view.TemplateService
}

func NewConsentController(hydraService *model.HydraService, tmplService *view.TemplateService) *ConsentController {
	return &ConsentController{
		hydraService: hydraService,
		tmplService:  tmplService,
	}
}

func (c *ConsentController) ConsentForm(w http.ResponseWriter, r *http.Request) {
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
		slog.Debug("ConsentForm", "skip", *consentRequest.Skip)
		skipConsent = *consentRequest.Skip
	}
	if !skipConsent && consentRequest.Client.SkipConsent != nil {
		slog.Debug("ConsentForm", "client_skip_consent", *consentRequest.Client.SkipConsent)
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

func (c *ConsentController) Consent(w http.ResponseWriter, r *http.Request) {
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
