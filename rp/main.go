package main

import (
	"log"
	"net/http"
	"os"
	"rp/config"
	"rp/routes"
)

func init() {
	id := os.Getenv("DEFAULT_CLIENT_ID")
	sec := os.Getenv("DEFAULT_CLIENT_SECRET")
	config.LoadOAuth2Config(id, sec)
}

func main() {
	r := routes.SetupRoutes()

	port := config.GetPort()
	log.Printf("Listening on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
