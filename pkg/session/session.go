/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package session contains tools to create and retrieve a VCenter session.
package session

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/blang/semver"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/xml"
	ctrl "sigs.k8s.io/controller-runtime"

	infrav1 "sigs.k8s.io/cluster-api-provider-vsphere/apis/v1beta1"
)

var (
	// global Session map against sessionKeys in map[sessionKey]Session.
	sessionCache sync.Map

	// mutex to control access to the GetOrCreate function to avoid duplicate
	// session creations on startup.
	sessionMU sync.Mutex
)

// Session is a vSphere session with a configured Finder.
type Session struct {
	*govmomi.Client
	Finder     *find.Finder
	datacenter *object.Datacenter
	TagManager *tags.Manager
}

// SOAPResponse represents the structure of SOAP responses
type SOAPResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		XMLName xml.Name `xml:"Body"`
		Fault   *struct {
			XMLName xml.Name `xml:"Fault"`
			Code    struct {
				XMLName xml.Name `xml:"faultcode"`
				Value   string   `xml:",chardata"`
			} `xml:"faultcode"`
			Reason struct {
				XMLName xml.Name `xml:"faultstring"`
				Value   string   `xml:",chardata"`
			} `xml:"faultstring"`
			Detail struct {
				XMLName xml.Name `xml:"detail"`
				Content string   `xml:",chardata"`
			} `xml:"detail"`
		} `xml:"Fault,omitempty"`
	} `xml:"Body"`
}

// CustomTransport wraps the default transport to intercept SOAP responses
type CustomTransport struct {
	http.RoundTripper
}

func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Call the original transport
	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}
	resp.Body.Close()

	// Check if it's a SOAP response
	if strings.Contains(string(body), "<soap:Envelope") || strings.Contains(string(body), "<Envelope") {
		var soapResp SOAPResponse
		if err := xml.Unmarshal(body, &soapResp); err == nil {
			if soapResp.Body.Fault != nil {
				log := ctrl.Log.WithName("vsphere-session")
				log.Error(nil, "=== SOAP FAULT DETECTED ===")
				log.Error(nil, "Fault Code: "+soapResp.Body.Fault.Code.Value)
				log.Error(nil, "Fault Reason: "+soapResp.Body.Fault.Reason.Value)
				log.Error(nil, "Fault Detail: "+soapResp.Body.Fault.Detail.Content)

				// Check if this is an authentication error
				if strings.Contains(strings.ToLower(soapResp.Body.Fault.Reason.Value), "incorrect user name or password") ||
					strings.Contains(strings.ToLower(soapResp.Body.Fault.Reason.Value), "cannot complete login") {
					log.Error(nil, "=== AUTHENTICATION ERROR DETECTED ===")
					log.Error(nil, "Please verify your vSphere username and password credentials")
					log.Error(nil, "================================================")
				}
				log.Error(nil, "================================")
			}
		}

		// Check for authentication-related error messages in the response
		bodyStr := string(body)
		authKeywords := []string{
			"incorrect user name or password", "cannot complete login", "invalidlogin",
			"authentication failed", "login failed", "invalid credentials",
		}
		for _, keyword := range authKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
				log := ctrl.Log.WithName("vsphere-session")
				log.Error(nil, fmt.Sprintf("=== AUTHENTICATION ISSUE DETECTED (keyword: %s) ===", keyword))
				log.Error(nil, "Response contains authentication-related content")
				log.Error(nil, "Please verify your vSphere username and password")
				log.Error(nil, "================================================")
				break
			}
		}

		// Check for privilege-related error messages in the response
		privilegeKeywords := []string{
			"privilege", "permission", "access denied", "unauthorized", "forbidden",
			"NoPermission", "InvalidPrivilege", "insufficient privileges",
		}
		for _, keyword := range privilegeKeywords {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
				log := ctrl.Log.WithName("vsphere-session")
				log.Error(nil, fmt.Sprintf("=== POTENTIAL PRIVILEGE ISSUE DETECTED (keyword: %s) ===", keyword))
				log.Error(nil, "Response contains privilege-related content")
				log.Error(nil, "Please verify user has sufficient vSphere permissions")
				log.Error(nil, "==================================================")
				break
			}
		}
	}

	// Create a new response with the body
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	return resp, nil
}

// Feature is a set of Features of the session.
type Feature struct{}

// DefaultFeature sets the default values for features.
func DefaultFeature() Feature {
	return Feature{}
}

// Params are the parameters of a VCenter session.
type Params struct {
	server     string
	datacenter string
	userinfo   *url.Userinfo
	thumbprint string
	feature    Feature
}

// NewParams returns an empty set of parameters with default features.
func NewParams() *Params {
	return &Params{
		feature: DefaultFeature(),
	}
}

// WithServer adds a server to parameters.
func (p *Params) WithServer(server string) *Params {
	p.server = server
	return p
}

// WithDatacenter adds a datacenter to parameters.
func (p *Params) WithDatacenter(datacenter string) *Params {
	p.datacenter = datacenter
	return p
}

// WithUserInfo adds userinfo to parameters.
func (p *Params) WithUserInfo(username, password string) *Params {
	p.userinfo = url.UserPassword(username, password)
	return p
}

// WithThumbprint adds a thumbprint to parameters.
func (p *Params) WithThumbprint(thumbprint string) *Params {
	p.thumbprint = thumbprint
	return p
}

// WithFeatures adds features to parameters.
func (p *Params) WithFeatures(feature Feature) *Params {
	p.feature = feature
	return p
}

// GetOrCreate gets a cached session or creates a new one if one does not
// already exist.
func GetOrCreate(ctx context.Context, params *Params) (*Session, error) {
	log := ctrl.LoggerFrom(ctx).WithValues(
		"server", params.server,
		"datacenter", params.datacenter,
		"username", params.userinfo.Username())
	ctx = ctrl.LoggerInto(ctx, log)

	sessionMU.Lock()
	defer sessionMU.Unlock()

	userPassword, _ := params.userinfo.Password()
	h := sha256.New()
	h.Write([]byte(userPassword))
	hashedUserPassword := h.Sum(nil)
	sessionKey := fmt.Sprintf("%s#%s#%s#%x", params.server, params.datacenter, params.userinfo.Username(),
		hashedUserPassword)
	if cachedSession, ok := sessionCache.Load(sessionKey); ok {
		s := cachedSession.(*Session)

		// Retrieve the current session from Managed Object.
		// The userSession is active when the value is not nil.
		userSession, err := s.SessionManager.UserSession(ctx)
		if err != nil {
			log.Error(err, "Failed to check if vim session is active")
		}

		tagManagerSession, err := s.TagManager.Session(ctx)
		if err != nil {
			log.Error(err, "Failed to check if REST session is active")
		}

		if userSession != nil && tagManagerSession != nil {
			log.Info("Found active cached vSphere client session")
			return s, nil
		}

		log.Info("Logout the REST session because it is inactive")
		if err := s.TagManager.Logout(ctx); err != nil {
			log.Error(err, "Failed to logout REST session")
		} else {
			log.Info("Logout REST session succeed")
		}

		log.Info("Logout the session because it is inactive")
		if err := s.Client.Logout(ctx); err != nil {
			log.Error(err, "Failed to logout session")
		} else {
			log.Info("Logout session succeed")
		}
	}

	// soap.ParseURL expects a valid URL. In the case of a bare, unbracketed
	// IPv6 address (e.g fd00::1) ParseURL will fail. Surround unbracketed IPv6
	// addresses with brackets.
	urlSafeServer := params.server
	ip, err := netip.ParseAddr(urlSafeServer)
	if err == nil && ip.Is6() {
		urlSafeServer = fmt.Sprintf("[%s]", urlSafeServer)
	}

	soapURL, err := soap.ParseURL(urlSafeServer)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create vCenter session: error parsing vSphere URL %q", params.server)
	}
	if soapURL == nil {
		return nil, errors.Errorf("failed to create vCenter session: error parsing vSphere URL %q: URL is nil", params.server)
	}

	soapURL.User = params.userinfo
	client, err := newClient(ctx, soapURL, params.thumbprint, params.feature)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create vCenter session")
	}

	session := Session{Client: client}
	session.UserAgent = infrav1.GroupVersion.String()

	// Assign the finder to the session.
	session.Finder = find.NewFinder(session.Client.Client, false)
	// Assign tag manager to the session.
	manager, err := newManager(ctx, client.Client, soapURL.User, params.feature)
	if err != nil {
		log.Error(err, "Failed to create tags manager, will logout")
		// Logout of previously logged session to not leak
		if errLogout := client.Logout(ctx); errLogout != nil {
			log.Error(errLogout, "Failed to logout of leading client session")
		}
		return nil, errors.Wrap(err, "failed to create vCenter session: failed to create tags manager")
	}
	session.TagManager = manager

	// Assign the datacenter if one was specified.
	if params.datacenter != "" {
		dc, err := session.Finder.Datacenter(ctx, params.datacenter)
		if err != nil {
			log.Error(err, "Failed to get datacenter, will logout")
			// Logout of previously logged session to not leak
			if errLogout := manager.Logout(ctx); errLogout != nil {
				log.Error(errLogout, "Failed to logout of leading REST session")
			}
			if errLogout := client.Logout(ctx); errLogout != nil {
				log.Error(errLogout, "Failed to logout of leading client session")
			}
			return nil, errors.Wrapf(err, "failed to create vCenter session: failed to find datacenter %q", params.datacenter)
		}
		session.datacenter = dc
		session.Finder.SetDatacenter(dc)
	}
	// Cache the session.
	sessionCache.Store(sessionKey, &session)

	log.Info("Created and cached vSphere client session", "server", params.server, "datacenter", params.datacenter, "username", params.userinfo.Username())

	return &session, nil
}

func newClient(ctx context.Context, url *url.URL, thumbprint string, _ Feature) (*govmomi.Client, error) {
	insecure := thumbprint == ""
	
	customTransport := &CustomTransport{
		RoundTripper: createTransport(insecure),
	}
	
	soapClient := soap.NewClient(url, insecure)
	soapClient.Transport = customTransport
	
	if !insecure {
		soapClient.SetThumbprint(url.Host, thumbprint)
	}

	vimClient, err := vim25.NewClient(ctx, soapClient)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create client")
	}
	vimClient.UserAgent = "k8s-capv-useragent"

	c := &govmomi.Client{
		Client:         vimClient,
		SessionManager: session.NewManager(vimClient),
	}

	if err := c.Login(ctx, url.User); err != nil {
		// Check if it's a credential-related error
		if strings.Contains(err.Error(), "incorrect user name or password") ||
			strings.Contains(err.Error(), "Cannot complete login") ||
			strings.Contains(err.Error(), "InvalidLogin") {
			return nil, errors.Wrapf(err, "vSphere authentication failed - please verify username and password")
		}
		return nil, errors.Wrapf(err, "failed to create client: failed to login")
	}

	return c, nil
}

// newManager creates a Manager that encompasses the REST Client for the VSphere tagging API.
func newManager(ctx context.Context, client *vim25.Client, user *url.Userinfo, _ Feature) (*tags.Manager, error) {
	rc := rest.NewClient(client)
	if err := rc.Login(ctx, user); err != nil {
		return nil, errors.Wrapf(err, "failed to create tags manager: failed to login REST client")
	}
	return tags.NewManager(rc), nil
}

// GetVersion returns the VCenterVersion.
func (s *Session) GetVersion() (infrav1.VCenterVersion, error) {
	svcVersion := s.ServiceContent.About.Version
	version, err := semver.New(svcVersion)
	if err != nil {
		return "", err
	}

	if version.Major >= 6 {
		return infrav1.NewVCenterVersion(svcVersion), nil
	}
	return "", unidentifiedVCenterVersion{version: svcVersion}
}

// Clear is meant to destroy all the cached sessions.
func Clear() {
	sessionCache.Range(func(_, s any) bool {
		cachedSession := s.(*Session)
		_ = cachedSession.Logout(context.Background())
		return true
	})
}

// FindByBIOSUUID finds an object by its BIOS UUID.
//
// To avoid comments about this function's name, please see the Golang
// WIKI https://github.com/golang/go/wiki/CodeReviewComments#initialisms.
// This function is named in accordance with the example "XMLHTTP".
func (s *Session) FindByBIOSUUID(ctx context.Context, uuid string) (object.Reference, error) {
	return s.findByUUID(ctx, uuid, false)
}

// FindByInstanceUUID finds an object by its instance UUID.
func (s *Session) FindByInstanceUUID(ctx context.Context, uuid string) (object.Reference, error) {
	return s.findByUUID(ctx, uuid, true)
}

func (s *Session) findByUUID(ctx context.Context, uuid string, findByInstanceUUID bool) (object.Reference, error) {
	if s.Client == nil {
		return nil, errors.New("vSphere client is not initialized")
	}
	si := object.NewSearchIndex(s.Client.Client)
	ref, err := si.FindByUuid(ctx, s.datacenter, uuid, true, &findByInstanceUUID)
	if err != nil {
		return nil, errors.Wrapf(err, "error finding object by uuid %q", uuid)
	}
	return ref, nil
}

// createTransport creates a transport that respects the insecure flag
func createTransport(insecure bool) http.RoundTripper {
	if insecure {
		// Create a transport that skips TLS verification
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		return transport
	}
	// Use default transport for secure connections
	return http.DefaultTransport
}
