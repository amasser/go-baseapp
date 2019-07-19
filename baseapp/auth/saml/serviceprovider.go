// Copyright 2019 Palantir Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/pkg/errors"
)

type OnErrorCallback func(*http.Request, error)

type OnLoginCallback func(http.ResponseWriter, *http.Request, *saml.Assertion)

type Settings struct {
	AssertionConsumerServicePath string
	SPMetadataPath               string
	CertificatePath              string
	KeyPath                      string
	IDPMetadataURL               string
	OnError                      OnErrorCallback
	OnLogin                      OnLoginCallback
	IDStore                      IDStore
}

// ServiceProvider is capable of handling a SAML login. It provides
// an http.Handler (via ACSHandler) which can process the http POST from the SAML IDP. It accepts callbacks for both error and
// success conditions so that clients can take action after the auth flow is complete. It also provides a handler
// for serving the service provider metadata XML.
type ServiceProvider struct {
	sp           *saml.ServiceProvider
	acsPath      string
	metadataPath string
	onError      OnErrorCallback
	onLogin      OnLoginCallback
	idStore      IDStore
}

// NewServiceProviderFromMetadata returns a ServiceProvider. The configuration of the ServiceProvider
// is a result of combinging settings provided to this method and values parsed from the IDP's metadata.
func NewServiceProviderFromMetadata(settings Settings) (*ServiceProvider, error) {
	e, err := getEntityFromMetadata(settings)

	if err != nil {
		return nil, errors.Wrap(err, "could not determine settings from IDP metadata")
	}

	certBytes, err := ioutil.ReadFile(settings.CertificatePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not read provided certificate file")
	}

	certPem, _ := pem.Decode(certBytes)
	if certPem == nil {
		return nil, errors.New("could not PEM decode the provided certificate")
	}

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse provided certificate")
	}

	keyBytes, err := ioutil.ReadFile(settings.KeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not read provided certificate file")
	}

	keyPem, _ := pem.Decode(keyBytes)
	if keyPem == nil {
		return nil, errors.New("could not PEM decode the provided private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse provided private key")
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("provided private key was not an RSA key")
	}

	provider := &saml.ServiceProvider{
		IDPMetadata: e,
		Certificate: cert,
		Key:         rsaKey,
	}
	sp := &ServiceProvider{
		sp:           provider,
		onError:      settings.OnError,
		onLogin:      settings.OnLogin,
		acsPath:      settings.AssertionConsumerServicePath,
		metadataPath: settings.SPMetadataPath,
		idStore:      settings.IDStore,
	}

	if sp.onError == nil {
		sp.onError = DefaultErrorCallback
	}

	if sp.onLogin == nil {
		sp.onLogin = DefaultLoginCallback
	}

	if sp.idStore == nil {
		sp.idStore = cookieIDStore{}
	}

	return sp, nil
}

func DefaultErrorCallback(r *http.Request, err error) {
	fmt.Println(err.Error())
}

func DefaultLoginCallback(w http.ResponseWriter, r *http.Request, resp *saml.Assertion) {
	w.WriteHeader(http.StatusOK)
}

func getEntityFromMetadata(settings Settings) (*saml.EntityDescriptor, error) {
	resp, err := http.Get(settings.IDPMetadataURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download IDP metadata")
	}

	defer func() { _ = resp.Body.Close() }()
	descriptor, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to download IDP metadata")
	}

	entity := &saml.EntityDescriptor{}

	if err := xml.Unmarshal(descriptor, entity); err != nil {
		return nil, errors.Wrap(err, "could not parse returned metadata")
	}

	return entity, nil
}

func (s *ServiceProvider) getSAMLSettingsForRequest(r *http.Request) *saml.ServiceProvider {

	//make a copy in case different requests have different host headers
	newSP := *s.sp

	u := url.URL{
		Host:   r.Host,
		Scheme: "http",
	}

	if r.TLS != nil {
		u.Scheme = "https"
	}

	u.Path = s.metadataPath
	newSP.MetadataURL = u
	u.Path = s.acsPath
	newSP.AcsURL = u

	return &newSP
}

// DoAuth takes an http.ResponseWriter that has not been written to yet, and conducts and SP initiated login
// If the flow proceeds correctly the user should be redirected to the handler provided by ACSHandler().
func (s *ServiceProvider) DoAuth(w http.ResponseWriter, r *http.Request) {
	sp := s.getSAMLSettingsForRequest(r)

	request, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	if err != nil {
		s.onError(r, errors.Wrap(err, "failed to create authentication request"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err := s.idStore.StoreID(w, request.ID); err != nil {
		s.onError(r, errors.Wrap(err, "failed to store SAML request id"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	target := request.Redirect("")

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// ACSHandler returns an http.Handler which is capable of validating and processing SAML Responses.
func (s *ServiceProvider) ACSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sp := s.getSAMLSettingsForRequest(r)
		if err := r.ParseForm(); err != nil {
			s.onError(r, errors.Wrap(err, "could not parse ACS form"))
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		id, err := s.idStore.GetID(r)
		if err != nil {
			s.onError(r, errors.Wrap(err, "could not retrieve id"))
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		assertion, err := sp.ParseResponse(r, []string{id})

		if err != nil {
			if parseErr, ok := err.(*saml.InvalidResponseError); ok {
				s.onError(r, errors.Wrap(parseErr.PrivateErr, "failed to validate SAML assertion"))
			} else {
				s.onError(r, errors.Wrap(err, "failed to parse SAML assertion"))
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		s.onLogin(w, r, assertion)
	})

}

// MetadataHandler returns an http.Handler which sends the generated metadata XML in response to a request
func (s *ServiceProvider) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md, err := xml.Marshal(s.getSAMLSettingsForRequest(r).Metadata())
		if err != nil {
			s.onError(r, errors.Wrap(err, "failed to generate service provider metadata"))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		if _, err := w.Write(md); err != nil {
			s.onError(r, errors.Wrap(err, "failed to write metadata to response"))
		}
	})
}
