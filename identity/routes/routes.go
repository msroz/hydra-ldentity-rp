package routes

import (
	"idp/controllers"
	"idp/model"
	"idp/view"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
)

func Setup(r *chi.Mux, store *sessions.CookieStore, hydraAdminURL string) {
	// Initialize services
	hydraService := model.NewHydraService(hydraAdminURL)
	tmplService := view.NewTemplateService("./templates")

	// Initialize controllers
	homeController := controllers.NewHomeController(tmplService)
	authController := controllers.NewAuthController(store, hydraService, tmplService)

	// Routes
	r.Get("/", homeController.Home)
	r.Get("/error", homeController.Error)

	r.Get("/login", authController.LoginForm)
	r.Post("/login", authController.Login)

	r.Get("/consent", authController.ConsentForm)
	r.Post("/consent", authController.Consent)

	r.Get("/post_logout", authController.PostLogout)
	r.Get("/logout", authController.LogoutForm)
	r.Post("/logout", authController.Logout)

	r.Post("/refresh_token_hook", authController.TokenHook)
}
