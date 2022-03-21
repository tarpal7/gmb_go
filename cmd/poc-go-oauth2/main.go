package main

import (
	"log"
	"net/http"

	"github.com/BNPrashanth/poc-go-oauth2/internal/configs"
	"github.com/BNPrashanth/poc-go-oauth2/internal/logger"
	"github.com/BNPrashanth/poc-go-oauth2/internal/services"

	"fmt"

	"github.com/spf13/viper"
)

func main() {
	// Initialize Viper across the application
	configs.InitializeViper()

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()

	// Initialize Oauth2 Services
	services.InitializeOAuthGoogle()

	// Routes for the application
	http.HandleFunc("/", services.HandleMain)
	http.HandleFunc("/login-gl", services.HandleGoogleLogin)
	http.HandleFunc("/locations", services.GetLocatios)
	http.HandleFunc("/locations/", services.GetLocationById)
	http.HandleFunc("/reviews/", services.GetReviewsByIdLocation)
	http.HandleFunc("/auth/google/callback", services.CallBackFromGoogle)
	fmt.Println(viper.GetString("port"))
	logger.Log.Info("Started running on http://localhost:" + viper.GetString("port"))
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
}
