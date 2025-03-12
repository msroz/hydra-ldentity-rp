package controllers

import (
	"net/http"
	"rp/config"
	"rp/model"
)

type HomeController struct{}

func NewHomeController() *HomeController {
	return &HomeController{}
}

// Home handles the home page
func (c *HomeController) Home(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := r.Cookie(loginSessionName)

	renderTemplate(w, "home.html", map[string]interface{}{
		"ClientID":     config.GetOAuth2Config().ClientID,
		"ClientSecret": config.GetOAuth2Config().ClientSecret,
		"Users":        model.Store.FindAll(),
		"LoginSession": loginSession,
		"Action":       "/clients",
	})
}
