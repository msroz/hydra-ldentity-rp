package controllers

import (
	"fmt"
	"idp/model"
	"idp/view"
	"net/http"
)

type HomeController struct {
	tmplService *view.TemplateService
}

func NewHomeController(tmplService *view.TemplateService) *HomeController {
	return &HomeController{
		tmplService: tmplService,
	}
}

func (c *HomeController) Home(w http.ResponseWriter, r *http.Request) {
	hydraSession, _ := r.Cookie("ory_hydra_session_dev")
	loginSession, _ := r.Cookie("identity_login_session")

	users := model.Store.FindAll()

	c.tmplService.RenderTemplate(w, "home.html", map[string]interface{}{
		"HydraSession": hydraSession,
		"LoginSession": loginSession,
		"Users":        users,
	})
}

func (c *HomeController) Error(w http.ResponseWriter, r *http.Request) {
	detail := r.URL.Query().Get("detail")
	fmt.Println("query", r.URL.Query())
	fmt.Println("detail", detail)
	c.tmplService.RenderTemplate(w, "error.html", map[string]interface{}{
		"Detail": detail,
	})
}
