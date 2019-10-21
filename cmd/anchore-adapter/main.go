package main

import (
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"
	api "github.com/anchore/harbor-scanner-adapter/pkg/http/api/v1"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func main() {
	// Load the adapter configuration, separate from the client config
	adapterConfig, err := adapter.GetConfig()
	if err != nil {
		log.WithField("err", err).Fatalf("no configuration found")
	}

	if adapterConfig.LogFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}

	log.SetLevel(adapterConfig.LogLevel)
	log.Info("Log level ", log.GetLevel())
	log.Info("Starting harbor-scanner-anchore")

	// Load the client configuration, which contains credentials for anchore api, so treated as a secret
	anchoreClientConfig, err := client.GetConfig()
	if err != nil {
		log.WithField("err", err).Fatalf("error loading anchore client configuration")
	}

	// Start the API service
	scanner, err := anchore.NewScanner(anchoreClientConfig)
	if err != nil {
		log.WithField("err", err).Fatalf("error instantiating scanner with configuration")
	}

	apiHandler := api.NewAPIHandler(scanner, adapterConfig)
	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	// Adds the authz middleware to process Bearer tokens if this is configured with an apikey
	v1Router.Use(apiHandler.AuthenticationMiddleware)
	v1Router.Use(apiHandler.LoggerMiddleware)

	// Simple routes defined by the Harbor adapter API spec
	v1Router.Methods("GET").Path("/metadata").HandlerFunc(apiHandler.GetMetadata)
	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{scanId}/report").HandlerFunc(apiHandler.GetScanReport)

	log.WithField("address", adapterConfig.ListenAddr).Info("listening for connections")
	err = http.ListenAndServe(adapterConfig.ListenAddr, router)
	if err != nil && err != http.ErrServerClosed {
		log.WithField("err", err).Fatalf("error in server listener")
	}
}
