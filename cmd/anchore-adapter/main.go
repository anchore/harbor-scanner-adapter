package main

import (
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore"
	api "github.com/anchore/harbor-scanner-adapter/pkg/http/api/v1"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {
	// Load the adapter configuration, separate from the client config
	adapterConfig, err := adapter.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	log.Printf("Starting harbor-scanner-anchore")

	// Load the client configuration, which contains credentials for anchore api, so treated as a secret
	anchoreClientConfig, err := anchore.GetConfig()
	if err != nil {
		log.Fatalf("Error loading anchore client configuration: %v", err)
	}

	// Start the API service
	scanner, err := anchore.NewScanner(anchoreClientConfig)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := api.NewAPIHandler(scanner, adapterConfig)
	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	// Adds the authz middleware to process Bearer tokens if this is configured with an apikey
	v1Router.Use(apiHandler.AuthenticationMiddleware)

	// Simple routes defined by the Harbor adapter API spec
	v1Router.Methods("GET").Path("/metadata").HandlerFunc(apiHandler.GetMetadata)
	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{scanId}/report").HandlerFunc(apiHandler.GetScanReport)

	log.Printf("Listening on address: %s", adapterConfig.ListenAddr)
	err = http.ListenAndServe(adapterConfig.ListenAddr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}
