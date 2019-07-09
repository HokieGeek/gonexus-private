package nexusiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	nexus "github.com/hokiegeek/gonexus"
	publiciq "github.com/hokiegeek/gonexus/iq"
)

const iqRestOrganizationPrivate = "rest/organization/%s"
const iqRestSessionPrivate = "rest/user/session"
const iqRestFirewallPrivate = "rest/repositories/%s/report/details"

// FirewallComponent is a component in the Firewall NotReport
type FirewallComponent struct {
	ComponentID          publiciq.ComponentIdentifier `json:"componentIdentifier"`
	ComponentDisplayText string                       `json:"componentDisplayText"`
	Pathname             string                       `json:"pathname"`
	Hash                 string                       `json:"hash"`
	MatchState           string                       `json:"matchState"`
	Quarantined          bool                         `json:"quarantined"`
	Waived               bool                         `json:"waived"`
	ThreatLevel          int                          `json:"threatLevel"`
	HighestThreatLevel   bool                         `json:"highestThreatLevel"`
	PolicyName           string                       `json:"policyName"`
}

// IQ holds basic and state info on the IQ Server we will connect to
type IQ struct {
	defaultServer nexus.DefaultServer
}

// New creates a new IQ instance
func New(host, username, password string) (*IQ, error) {
	iq := new(IQ)
	iq.defaultServer.Host = host
	iq.defaultServer.Username = username
	iq.defaultServer.Password = password
	return iq, nil
}

// FromPublic creates a private IQ instance from a public one
func FromPublic(iq publiciq.IQ) (*IQ, error) {
	priv := new(IQ)
	priv.defaultServer.Host = iq.Host
	priv.defaultServer.Username = iq.Username
	priv.defaultServer.Password = iq.Password
	return priv, nil
}

// NewRequest creates an http.Request object with private session
func (iq *IQ) NewRequest(method, endpoint string, payload io.Reader) (*http.Request, error) {
	req, err := iq.defaultServer.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, err
	}

	_, resp, err := iq.defaultServer.Get(iqRestSessionPrivate)
	if err != nil {
		return nil, err
	}

	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
		if cookie.Name == "CLM-CSRF-TOKEN" {
			req.Header.Add("X-CSRF-TOKEN", cookie.Value)
		}
	}

	return req, nil
}

// Do performs an http.Request and reads the body if StatusOK
func (iq *IQ) Do(request *http.Request) ([]byte, *http.Response, error) {
	return iq.defaultServer.Do(request)
}

func (iq *IQ) http(method, endpoint string, payload io.Reader) ([]byte, *http.Response, error) {
	request, err := iq.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, nil, err
	}

	return iq.Do(request)
}

// Get performs an HTTP GET against the indicated endpoint
func (iq IQ) Get(endpoint string) ([]byte, *http.Response, error) {
	return iq.http("GET", endpoint, nil)
}

// Post performs an HTTP POST against the indicated endpoint
func (iq IQ) Post(endpoint string, payload []byte) ([]byte, *http.Response, error) {
	return iq.http("POST", endpoint, bytes.NewBuffer(payload))
}

// Put performs an HTTP PUT against the indicated endpoint
func (iq IQ) Put(endpoint string, payload []byte) ([]byte, *http.Response, error) {
	return iq.http("PUT", endpoint, bytes.NewBuffer(payload))
}

// Del performs an HTTP DELETE against the indicated endpoint
func (iq IQ) Del(endpoint string) (resp *http.Response, err error) {
	_, resp, err = iq.http("DELETE", endpoint, nil)
	return
}

func createTempApplication(iq nexus.Server) (orgID string, appName string, appID string, err error) {
	rand.Seed(time.Now().UnixNano())
	name := strconv.Itoa(rand.Int())

	orgID, err = publiciq.CreateOrganization(iq, name)
	if err != nil {
		return
	}

	appName = fmt.Sprintf("%s_app", name)

	appID, err = publiciq.CreateApplication(iq, appName, orgID)
	if err != nil {
		return
	}

	return
}

func deleteTempApplication(iq IQ, applicationPublicID string) error {
	appInfo, err := publiciq.GetApplicationDetailsByPublicID(iq, applicationPublicID)
	if err != nil {
		return err
	}

	if err := publiciq.DeleteApplication(iq, appInfo.ID); err != nil {
		return err
	}

	DeleteOrganization(iq, appInfo.OrganizationID) // OJO: Gonna go ahead and ignore this error for now

	return nil
}

// DeleteOrganization deletes an organization in IQ with the given id
func DeleteOrganization(iq IQ, organizationID string) error {
	endpoint := fmt.Sprintf(iqRestOrganizationPrivate, organizationID)

	resp, err := iq.Del(endpoint)
	if err != nil && resp.StatusCode != http.StatusNoContent {
		return err
	}

	return nil
}

// EvaluateComponentsAsFirewall evaluates the list of components using Root Organization only
func EvaluateComponentsAsFirewall(iq IQ, components []publiciq.Component) (eval *publiciq.Evaluation, err error) {
	// Create temp application
	_, appName, appID, err := createTempApplication(iq)
	if err != nil {
		return
	}
	defer deleteTempApplication(iq, appName)

	// Evaluate components
	eval, err = publiciq.EvaluateComponents(iq.defaultServer, components, appID)
	if err != nil {
		return
	}

	return
}

// GetFirewallState returns the components in a Firewalled proxy
func GetFirewallState(iq *IQ, repoid string) (c []FirewallComponent, err error) {
	endpoint := fmt.Sprintf(iqRestFirewallPrivate, repoid)

	body, _, err := iq.Get(endpoint)
	if err = json.Unmarshal(body, &c); err != nil {
		return
	}

	return
}
