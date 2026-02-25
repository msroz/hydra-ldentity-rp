package controllers

import (
	"log/slog"
	"net/http"
	"net/url"
	"rp/auth"
	"rp/config"
	"rp/httputil"
	"rp/model"
	"rp/view"
	"strconv"

	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/ory/x/urlx"
	"golang.org/x/oauth2"
)

type LogoutController struct {
	store       *sessions.CookieStore
	oauth2Conf  oauth2.Config
	tmplService *view.TemplateService
}

func NewLogoutController(store *sessions.CookieStore, oauth2Conf oauth2.Config, tmplService *view.TemplateService) *LogoutController {
	return &LogoutController{
		store:       store,
		oauth2Conf:  oauth2Conf,
		tmplService: tmplService,
	}
}

func (c *LogoutController) Logout(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	id, _ := strconv.Atoi(query.Get("id"))

	usr, exist := model.Store.Find(model.ID(id))
	err := ""
	if !exist {
		err = "User not found"
	}

	u, _ := url.Parse(config.GetHydraSessionsLogoutURL())
	u = urlx.SetQuery(u, url.Values{
		"id_token_hint":            []string{usr.IDToken},
		"post_logout_redirect_uri": []string{config.GetLogoutCallbackURL()},
		"client_id":                []string{c.oauth2Conf.ClientID},
	})

	c.tmplService.RenderTemplate(w, "logout.html", map[string]interface{}{
		"LogoutURL": u.String(),
		"Error":     err,
	})
}

func (c *LogoutController) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	slog.Debug("logout callback", "state", state)
	// TODO: Check state

	session, _ := c.store.Get(r, loginSessionName)
	session.Options.MaxAge = -1
	session.Save(r, w)

	c.tmplService.RenderTemplate(w, "complete_logout.html", map[string]interface{}{})
}

func (c *LogoutController) BackchannelLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.ParseForm()

	logoutToken := r.FormValue("logout_token")
	set, err := auth.FetchHydraJWKs(ctx)
	if err != nil {
		httputil.HandleError(w, "failed to fetch JWKS", http.StatusInternalServerError, err)
		return
	}

	verifiedToken, err := jwt.ParseString(logoutToken, jwt.WithKeySet(set, jws.WithRequireKid(true)))
	if err != nil {
		httputil.HandleError(w, "failed to verify JWS", http.StatusInternalServerError, err)
		return
	}

	s, exist := verifiedToken.Get("sid")
	if !exist {
		httputil.HandleError(w, "sid not found in logout token", http.StatusInternalServerError, nil)
		return
	}
	sid, ok := s.(string)
	if !ok {
		httputil.HandleError(w, "sid is not string in logout token", http.StatusInternalServerError, nil)
		return
	}

	slog.Info("backchannel logout completed", "sid", sid)
	w.WriteHeader(http.StatusOK)
}
