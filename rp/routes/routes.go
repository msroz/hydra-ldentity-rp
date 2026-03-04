package routes

import (
	"net/http"
	"rp/controllers"
	"rp/view"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// SetupRoutes configures all the routes for the application
func SetupRoutes(store *sessions.CookieStore, oauth2Conf oauth2.Config, tmplService *view.TemplateService) *chi.Mux {
	r := chi.NewRouter()

	// Initialize controllers
	homeController := controllers.NewHomeController(tmplService)
	authController := controllers.NewAuthController(store, oauth2Conf, tmplService)
	logoutController := controllers.NewLogoutController(store, oauth2Conf, tmplService)
	clientController := controllers.NewClientController()

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Home routes
	r.Get("/", homeController.Home)

	// Auth routes
	r.Get("/initiate", authController.Initiate)
	r.Get("/reauth", authController.Reauth)
	r.Get("/callback", authController.Callback)
	r.Post("/token_exchange", authController.TokenExchange)

	// Logout routes
	r.Get("/logout", logoutController.Logout)
	r.Get("/logout_callback", logoutController.LogoutCallback)
	r.Post("/backchannel_logout", logoutController.BackchannelLogout)

	// Client routes
	r.Post("/clients", clientController.SaveClient)
	r.Get("/.well-known/jwks.json", clientController.GetJWKS)

	return r
}
