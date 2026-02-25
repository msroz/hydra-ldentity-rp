package main

import (
	"idp/config"
	"idp/routes"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("keep-session-store-key-secret"))

func init() {
	config.Load()
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	r := chi.NewRouter()

	// Setup CSRF protection
	csrfMiddleware := csrf.Protect(
		[]byte("keep-csrf-key-secret"),
		csrf.TrustedOrigins([]string{"127.0.0.1:3000"}),
	)
	r.Use(csrfMiddleware)

	// Setup routes
	routes.Setup(r, store, config.GetHydraAdminURL())

	port := config.GetPort()
	log.Println("Listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
