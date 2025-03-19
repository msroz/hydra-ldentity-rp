package routes

import (
	"rp/controllers"

	"github.com/go-chi/chi/v5"
)

// SetupRoutes configures all the routes for the application
func SetupRoutes() *chi.Mux {
	r := chi.NewRouter()

	// Initialize controllers
	homeController := controllers.NewHomeController()
	authController := controllers.NewAuthController()
	clientController := controllers.NewClientController()

	// Home routes
	r.Get("/", homeController.Home)
	r.Get("/error", homeController.Error)

	// Auth routes
	r.Get("/initiate", authController.Initiate)
	r.Get("/callback", authController.Callback)
	r.Get("/logout", authController.Logout)
	r.Get("/logout_callback", authController.LogoutCallback)
	r.Post("/backchannel_logout", authController.BackchannelLogout)

	// Native app routes
	r.Get("/native/initiate", authController.InitiateNative)

	// Client routes
	r.Post("/clients", clientController.SaveClient)
	r.Get("/.well-known/jwks.json", clientController.GetJWKS)
	r.Get("/.well-known/apple-app-site-association", clientController.GetAppleAppSiteAssociation)

	return r
}
