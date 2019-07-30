package privateiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"mime"
	"net/http"
	"strconv"
	"time"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const (
	restOrganizationPrivate = "rest/organization/%s"
	restFirewallPrivate     = "rest/repositories/%s/report/details"
	restWebhooks            = "rest/config/webhook"
	restSupportZip          = "rest/support?noLimit=true"
	restLicense             = "rest/product/license"
)

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

// Webhook event types
const (
	WebhookEventAppEval          = "Application Evaluation"
	WebhookEventPolicyMgmt       = "Policy Management"
	WebhookEventViolationAlert   = "Violation Alert"
	WebhookEventLicenseOverride  = "License Override Management"
	WebhookEventSecurityOverride = "Security Vulnerability Override Management"
)

// Webhook is the payload associated with creating an IQ webhook
type Webhook struct {
	ID         string   `json:"id,omitempty"`
	URL        string   `json:"url"`
	SecretKey  string   `json:"secretKey"`
	EventTypes []string `json:"eventTypes"`
}

func createTempApplication(iq publiciq.IQ) (orgID string, appName string, appID string, err error) {
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

func deleteTempApplication(iq publiciq.IQ, applicationPublicID string) error {
	appInfo, err := publiciq.GetApplicationByPublicID(iq, applicationPublicID)
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
func DeleteOrganization(iq publiciq.IQ, organizationID string) error {
	endpoint := fmt.Sprintf(restOrganizationPrivate, organizationID)

	resp, err := FromPublic(iq).Del(endpoint)
	if err != nil && resp.StatusCode != http.StatusNoContent {
		return err
	}

	return nil
}

// EvaluateComponentsWithRootOrg evaluates the list of components using Root Organization only
func EvaluateComponentsWithRootOrg(iq publiciq.IQ, components []publiciq.Component) (eval *publiciq.Evaluation, err error) {
	// Create temp application
	_, appName, appID, err := createTempApplication(iq)
	if err != nil {
		return
	}
	defer deleteTempApplication(iq, appName)

	// Evaluate components
	eval, err = publiciq.EvaluateComponents(iq, components, appID)
	if err != nil {
		return
	}

	return
}

// GetFirewallState returns the components in a Firewalled proxy
func GetFirewallState(iq publiciq.IQ, repoid string) (c []FirewallComponent, err error) {
	endpoint := fmt.Sprintf(restFirewallPrivate, repoid)

	body, _, err := FromPublic(iq).Get(endpoint)
	if err = json.Unmarshal(body, &c); err != nil {
		return
	}

	return
}

// InstallLicense allows for an IQ license to be installed
func InstallLicense(iq publiciq.IQ, license []byte) error {
	// --form "file=@${license}"
	_, _, err := FromPublic(iq).Post(restWebhooks, bytes.NewBuffer(license))
	return err
}

// GetSupportZip generates a support zip with the given options
func GetSupportZip(iq publiciq.IQ) ([]byte, string, error) {
	body, resp, err := FromPublic(iq).Get(restSupportZip)
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving support zip: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("error retrieving support zip: %s", resp.Status)
	}

	_, params, err := mime.ParseMediaType(resp.Header["Content-Disposition"][0])
	if err != nil {
		return nil, "", fmt.Errorf("error determining name of support zip: %v", err)
	}

	return body, params["filename"], nil
}

// CreateWebhook creates a webhook in IQ
func CreateWebhook(iq publiciq.IQ, url, secret string, eventTypes []string) error {
	request := Webhook{URL: url, SecretKey: secret, EventTypes: eventTypes}

	json, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, _, err = FromPublic(iq).Post(restWebhooks, bytes.NewBuffer(json))
	return err
}
