package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// Forbidden error represents a forbidden access error.
var ErrForbidden = errors.New("forbidden: you've been logged out")

// ISamlService defines the SAML Service interface.
type ISamlService interface {
	Login(ctx context.Context, relayState string) (string, error)
	ValidateCallback(ctx context.Context, body GoogleSamlCallbackResponse) (*SamlProfile, error)
}

// SamlProfile represents the user profile information received from the IdP.
type SamlProfile struct {
	FirstName  string
	LastName   string
	Attributes map[string]string
}

// GoogleSamlServiceOptions holds the configuration options for Google SAML.
type GoogleSamlServiceOptions struct {
	Certificate       string
	EntryPoint        string `mapstructure:"entry_point"`
	EntityID          string `mapstructure:"entity_id"`
	CertificatePath   string `mapstructure:"certificate_path"`
	CallbackURL       string `mapstructure:"callback_url"`
	AdminPanelBaseURL string `mapstructure:"admin_panel_base_url"`
}

type GoogleSamlCallbackResponse struct {
	RelayState   string `form:"RelayState"`
	SAMLResponse string `form:"SAMLResponse"`
}

// GoogleSamlService implements the ISamlService interface for Google SAML authentication.
type GoogleSamlService struct {
	app    *saml2.SAMLServiceProvider
	config GoogleSamlServiceOptions
}

// NewGoogleSamlService creates a new instance of GoogleSamlService.
func NewGoogleSamlService(config GoogleSamlServiceOptions) (*GoogleSamlService, error) {
	// Decode the certificate
	block, _ := pem.Decode([]byte(config.Certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create a certificate store and add the certificate
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}

	// Set up SAML service provider
	samlSP := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      config.EntryPoint,
		IdentityProviderIssuer:      config.EntityID,
		ServiceProviderIssuer:       config.EntityID,
		AssertionConsumerServiceURL: config.CallbackURL,
		SignAuthnRequests:           false,
		IDPCertificateStore:         &certStore,
		// AllowIDPInitiated:             true,
	}

	return &GoogleSamlService{
		app:    samlSP,
		config: config,
	}, nil
}

// Login initiates a login process for SAML Authentication.
func (s *GoogleSamlService) Login(ctx context.Context, relayState string) (string, error) {
	authnRequestURL, err := s.app.BuildAuthURL(relayState)
	if err != nil {
		return "", fmt.Errorf("failed to generate SAML login URL: %w", err)
	}
	return authnRequestURL, nil
}

// ValidateCallback validates the SAML callback from the IdP.
func (s *GoogleSamlService) ValidateCallback(ctx context.Context, body GoogleSamlCallbackResponse) (*SamlProfile, error) {
	assertionInfo, err := s.app.RetrieveAssertionInfo(body.SAMLResponse)
	if err != nil {
		return nil, fmt.Errorf("SAML validation failed: %w", err)
	}

	if assertionInfo.WarningInfo.InvalidTime {
		return nil, ErrForbidden
	}

	profile := &SamlProfile{
		FirstName: assertionInfo.Values.Get("firstName"),
		LastName:  assertionInfo.Values.Get("lastName"),
		Attributes: map[string]string{
			"first_name": assertionInfo.Values.Get("firstName"),
			"last_name":  assertionInfo.Values.Get("lastName"),
			"email":      assertionInfo.Values.Get("email"),
			"id":         assertionInfo.Values.Get("id"),
		},
	}

	return profile, nil
}
