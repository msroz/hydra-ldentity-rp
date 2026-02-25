package controllers

import (
	"net/http"
	"rp/config"
	"rp/model"
	"rp/view"
)

type HomeController struct {
	tmplService *view.TemplateService
}

func NewHomeController(tmplService *view.TemplateService) *HomeController {
	return &HomeController{
		tmplService: tmplService,
	}
}

// Home handles the home page
func (c *HomeController) Home(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := r.Cookie(loginSessionName)

	c.tmplService.RenderTemplate(w, "home.html", map[string]interface{}{
		"ClientID":     config.GetOAuth2Config().ClientID,
		"ClientSecret": config.GetOAuth2Config().ClientSecret,
		"Users":        model.Store.FindAll(),
		"LoginSession": loginSession,
		"Action":       "/clients",
	})
}
