package privateiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"mime/multipart"
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
	restAutoApps            = "rest/config/automaticApplications"
	restSystemNotice        = "rest/config/systemNotice"
	restReportReevaluate    = "rest/report/%s/%s/reevaluatePolicy"
	restMonitoringOrg       = "rest/policyMonitoring/organization/%s"
	restMonitoringApp       = "rest/policyMonitoring/application/%s"
	restMonitoringTrigger   = "rest/tasks/triggerPolicyMonitor"
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

type enableAutoAppsRequest struct {
	Enabled              bool   `json:"enabled"`
	ParentOrganizationID string `json:"parentOrganizationId"`
}

type systemNotice struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Enabled bool   `json:"enabled"`
}

type policyMonitoringRequest struct {
	StageTypeID string `json:"stageTypeId"`
}

/*
type policyMonitoringResponse struct {
	ID          string `json:"id"`
	OwnerID     string `json:"ownerId"`
	StageTypeID string `json:"stageTypeId"`
}*/

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
func InstallLicense(iq publiciq.IQ, license io.Reader) error {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	fw, err := w.CreateFormFile("file", "file")
	if err != nil {
		return fmt.Errorf("could not create form file: %v", err)
	}

	if _, err := io.Copy(fw, license); err != nil {
		return fmt.Errorf("could not create form file: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("could not create form file: %v", err)
	}

	piq := FromPublic(iq)
	req, err := piq.NewRequest("POST", restLicense, &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if err != nil {
		return fmt.Errorf("could not send license request: %v", err)
	}

	if _, resp, err := piq.Do(req); err != nil && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("could not send license request: %v", err)
	}

	return nil
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

	str, err := json.Marshal(request)
	if err != nil {
		return err
	}
	_, _, err = FromPublic(iq).Post(restWebhooks, bytes.NewBuffer(str))
	return err
}

// EnableAutomaticApplications enables automatic applications for the given organization
func EnableAutomaticApplications(iq publiciq.IQ, orgName string) error {
	org, err := publiciq.GetOrganizationByName(iq, orgName)
	if err != nil {
		return err
	}

	str, err := json.Marshal(enableAutoAppsRequest{true, org.ID})
	if err != nil {
		return err
	}

	_, _, err = FromPublic(iq).Put(restAutoApps, bytes.NewBuffer(str))
	return err
}

// DisableAutomaticApplications enables automatic applications for the given organization
func DisableAutomaticApplications(iq publiciq.IQ) error {
	str, err := json.Marshal(enableAutoAppsRequest{Enabled: false})
	if err != nil {
		return err
	}

	_, _, err = FromPublic(iq).Put(restAutoApps, bytes.NewBuffer(str))
	return err
}

// EnableNotice sets a message in IQ
func EnableNotice(iq publiciq.IQ, text string) error {
	str, err := json.Marshal(systemNotice{ID: "system-notice", Enabled: true, Message: text})
	if err != nil {
		return err
	}
	_, _, err = FromPublic(iq).Put(restSystemNotice, bytes.NewBuffer(str))
	return err
}

// DisableNotice disables the system notice
func DisableNotice(iq publiciq.IQ) error {
	str, err := json.Marshal(systemNotice{ID: "system-notice", Enabled: false})
	if err != nil {
		return err
	}
	_, _, err = FromPublic(iq).Put(restSystemNotice, bytes.NewBuffer(str))
	return err
}

// ReevaluateReport hits the re-eval button
func ReevaluateReport(iq publiciq.IQ, appID, stage string) error {
	info, err := publiciq.GetReportInfoByAppIDStage(iq, appID, stage)
	if err != nil {
		return fmt.Errorf("did not find report for '%s' at '%s' build stage: %v", appID, stage, err)
	}

	endpoint := fmt.Sprintf(restReportReevaluate, appID, info.ReportID())
	_, _, err = FromPublic(iq).Post(endpoint, nil)
	return err
}

// ReevaluateAllReports hits the re-eval button on AllTheThings!
func ReevaluateAllReports(iq publiciq.IQ) error {
	apps, err := publiciq.GetAllApplications(iq)
	if err != nil {
		return fmt.Errorf("could not retrieve applications: %v", err)
	}

	for _, app := range apps {
		if err != nil {
			continue
		}
		var infos []publiciq.ReportInfo
		if infos, err = publiciq.GetReportInfosByAppID(iq, app.PublicID); err == nil {
			for _, info := range infos {
				endpoint := fmt.Sprintf(restReportReevaluate, app.PublicID, info.ReportID())
				_, _, err = FromPublic(iq).Post(endpoint, nil)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("could not retrieve application: %v", err)
	}

	return nil
}

// EnableContinuousMonitoringApplication will enable Continuous Monitoring for the given application
func EnableContinuousMonitoringApplication(iq publiciq.IQ, appPublicID, stage string) error {
	app, err := publiciq.GetApplicationByPublicID(iq, appPublicID)
	if err != nil {
		return err
	}

	buf, err := json.Marshal(policyMonitoringRequest{stage})
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(restMonitoringApp, app.ID)
	_, _, err = FromPublic(iq).Put(endpoint, bytes.NewBuffer(buf))
	return nil
}

// EnableContinuousMonitoringOrganization will enable Continuous Monitoring for the given organization
func EnableContinuousMonitoringOrganization(iq publiciq.IQ, orgName, stage string) error {
	org, err := publiciq.GetOrganizationByName(iq, orgName)
	if err != nil {
		return err
	}

	buf, err := json.Marshal(policyMonitoringRequest{stage})
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(restMonitoringOrg, org.ID)
	_, _, err = FromPublic(iq).Put(endpoint, bytes.NewBuffer(buf))
	return err
}

// DisableContinuousMonitoringApplication will enable Continuous Monitoring for the given application
func DisableContinuousMonitoringApplication(iq publiciq.IQ, appPublicID string) error {
	app, err := publiciq.GetApplicationByPublicID(iq, appPublicID)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(restMonitoringApp, app.ID)
	_, err = FromPublic(iq).Del(endpoint)
	return err
}

// DisableContinuousMonitoringOrganization will enable Continuous Monitoring for the given organization
func DisableContinuousMonitoringOrganization(iq publiciq.IQ, orgName string) error {
	org, err := publiciq.GetOrganizationByName(iq, orgName)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf(restMonitoringOrg, org.ID)
	_, err = FromPublic(iq).Del(endpoint)
	return err
}

// TriggerContinuousMonitoring will test trigger continuous monitoring
func TriggerContinuousMonitoring(iq publiciq.IQ) error {
	_, _, err := FromPublic(iq).Post(restMonitoringTrigger, nil)
	return err
}

// POST rest/label/organization/ROOT_ORGANIZATION_ID
// {"id":null,"ownerId":null,"label":"foo","labelLowercase":null,"color":"light-red","description":"bar"}
