package routes

import (
	"idp/controllers"
	"idp/model"
	"idp/view"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
)

func Setup(r *chi.Mux, store *sessions.CookieStore, hydraAdminURL string) {
	// Initialize services
	hydraService := model.NewHydraService(hydraAdminURL)
	tmplService := view.NewTemplateService("./templates")

	// Initialize controllers
	homeController := controllers.NewHomeController(tmplService)
	loginController := controllers.NewLoginController(store, hydraService, tmplService)
	consentController := controllers.NewConsentController(hydraService, tmplService)
	logoutController := controllers.NewLogoutController(hydraService, tmplService)
	hookController := controllers.NewHookController(hydraService)

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Routes
	r.Get("/", homeController.Home)
	r.Get("/error", homeController.Error)

	r.Get("/login", loginController.LoginForm)
	r.Post("/login", loginController.Login)

	r.Get("/consent", consentController.ConsentForm)
	r.Post("/consent", consentController.Consent)

	r.Get("/post_logout", logoutController.PostLogout)
	r.Get("/logout", logoutController.LogoutForm)
	r.Post("/logout", logoutController.Logout)

	r.Post("/refresh_token_hook", hookController.TokenHook)
}
