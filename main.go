package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	Saml GoogleSamlServiceOptions `mapstructure:"saml"`
}

// LoadConfig loads the configuration from a config file using Viper.
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".") // Add current directory as config path

	// Read in the config file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	} else {
		fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	}

	// Unmarshal the config into a Config struct
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode into struct: %w", err)
	}

	// Load the certificate from file
	certData, err := os.ReadFile(config.Saml.CertificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Set the certificate content directly in the configuration
	config.Saml.Certificate = string(certData)

	return &config, nil
}

// Initialize your SAML service with necessary options
func initializeSamlService(conf *Config) (*GoogleSamlService, error) {
	config := GoogleSamlServiceOptions{
		EntryPoint:  conf.Saml.EntryPoint,  // Your IdP SSO URL
		EntityID:    conf.Saml.EntityID,    // Your Entity ID
		Certificate: conf.Saml.Certificate, // Your certificate string
		CallbackURL: conf.Saml.CallbackURL, // Your callback URL
	}

	return NewGoogleSamlService(config)
}

func main() {
	config, err := LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	// Initialize the SAML service
	samlService, err := initializeSamlService(config)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize SAML service: %v", err))
	}

	// Create a new Gin router
	r := gin.Default()

	// Define the login endpoint
	r.GET("/saml/login", func(c *gin.Context) {
		relayState := c.Query("relayState") // Relay state from query parameter

		loginURL, err := samlService.Login(context.Background(), relayState)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate SAML login"})
			return
		}

		// Redirect to the generated SAML login URL
		c.Redirect(http.StatusFound, loginURL)
	})

	// Define the callback endpoint
	r.POST("/saml/callback", func(c *gin.Context) {
		var form GoogleSamlCallbackResponse

		if err := c.ShouldBind(&form); err != nil {
			fmt.Println("Binding Error:", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to bind form data"})
			return
		}

		profile, err := samlService.ValidateCallback(context.Background(), form)
		if err != nil {
			if err == ErrForbidden {
				c.JSON(http.StatusForbidden, gin.H{"error": "You've been logged out"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "SAML validation failed"})
			}
			return
		}

		// Return the profile information as JSON
		c.JSON(http.StatusOK, gin.H{
			"first_name": profile.FirstName,
			"last_name":  profile.LastName,
			"attributes": profile.Attributes,
		})
	})

	// Run the Gin server on port 8080
	r.Run(":8080")
}
