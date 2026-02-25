package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"rp/config"
	"rp/routes"
	"rp/view"

	"github.com/gorilla/sessions"
)

func init() {
	id := os.Getenv("DEFAULT_CLIENT_ID")
	sec := os.Getenv("DEFAULT_CLIENT_SECRET")
	config.LoadOAuth2Config(id, sec)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	store := sessions.NewCookieStore([]byte("keep-session-store-key-secret"))
	tmplService := view.NewTemplateService("./templates")

	r := routes.SetupRoutes(store, config.GetOAuth2Config(), tmplService)

	port := config.GetPort()
	log.Printf("Listening on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
