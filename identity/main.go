package main

import (
	"idp/routes"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/ory/common/env"
)

const (
	port             = "3000"
	loginSessionName = "identity_login_session"
)

var (
	hydraAdminURL string
	store         = sessions.NewCookieStore([]byte("keep-session-store-key-secret"))
)

func init() {
	hydraAdminURL = os.Getenv("HYDRA_ADMIN_URL")
	if hydraAdminURL == "" {
		log.Fatal("HYDRA_ADMIN_URL environment variable not set")
	}
}

func main() {
	r := chi.NewRouter()

	// Setup CSRF protection
	csrfMiddleware := csrf.Protect([]byte("keep-csrf-key-secret"))
	r.Use(csrfMiddleware)

	// Setup routes
	routes.Setup(r, store, hydraAdminURL)

	log.Println("Listening on :" + env.Getenv("PORT", port))
	log.Fatal(http.ListenAndServe(":"+env.Getenv("PORT", port), r))
}
