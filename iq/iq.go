package nexusiq

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
	// "net/http/httputil"

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
	publiciq.IQ
}

func (iq *IQ) createTempApplication() (orgID string, appName string, appID string, err error) {
	rand.Seed(time.Now().UnixNano())
	name := strconv.Itoa(rand.Int())

	orgID, err = iq.CreateOrganization(name)
	if err != nil {
		return
	}

	appName = fmt.Sprintf("%s_app", name)

	appID, err = iq.CreateApplication(appName, orgID)
	if err != nil {
		return
	}

	return
}

func (iq *IQ) deleteTempApplication(applicationName string) error {
	appInfo, err := iq.GetApplicationDetailsByName(applicationName)
	if err != nil {
		return err
	}

	if err := iq.DeleteApplication(appInfo.ID); err != nil {
		return err
	}

	if err := iq.DeleteOrganization(appInfo.OrganizationID); err != nil {
		return err
	}

	return nil
}

func (iq *IQ) newPrivateRequest(method, endpoint string, payload io.Reader) (*http.Request, error) {
	req, err := iq.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, err
	}

	_, resp, err := iq.Get(iqRestSessionPrivate)
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

// DeleteOrganization deletes an organization in IQ with the given id
func (iq *IQ) DeleteOrganization(organizationID string) error {
	url := fmt.Sprintf(iqRestOrganizationPrivate, organizationID)

	req, err := iq.newPrivateRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	_, resp, err := iq.Do(req)
	if err != nil && resp.StatusCode != http.StatusNoContent {
		return err
	}

	return nil
}

// EvaluateComponentsAsFirewall evaluates the list of components using Root Organization only
func (iq *IQ) EvaluateComponentsAsFirewall(components []publiciq.Component) (eval *publiciq.Evaluation, err error) {
	// Create temp application
	_, appName, appID, err := iq.createTempApplication()
	if err != nil {
		return
	}
	defer iq.deleteTempApplication(appName)

	// Evaluate components
	eval, err = iq.EvaluateComponents(components, appID)
	if err != nil {
		return
	}

	return
}

// GetFirewallState returns the components in a Firewalled proxy
func (iq *IQ) GetFirewallState(repoid string) (c []FirewallComponent, err error) {
	url := fmt.Sprintf(iqRestFirewallPrivate, organizationID)

	req, err := iq.newPrivateRequest("GET", url, nil)
	if err != nil {
		return err
	}

	_, resp, err := iq.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)

		if err = json.Unmarshal(body, &c); err != nil {
			return
		}
	}

	return
}

// New creates a new IQ instance
func New(host, username, password string) (*IQ, error) {
	iq := new(IQ)
	iq.Host = host
	iq.Username = username
	iq.Password = password
	return iq, nil
}
