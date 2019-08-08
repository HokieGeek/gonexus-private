package privateiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const (
	restPolicyExportPrivate = "rest/policy/organization/%s/export"
	restPolicyImportPrivate = "rest/policy/organization/%s/import"
)

// IQPolicySet encapsulates the IQ policies
type IQPolicySet struct {
	Policies []struct {
		Actions struct {
			Proxy        string `json:"proxy"`
			Build        string `json:"build"`
			StageRelease string `json:"stage-release"`
			Release      string `json:"release"`
			Operate      string `json:"operate"`
			Develop      string `json:"develop"`
		} `json:"actions,omitempty"`
		Constraints []struct {
			Conditions []struct {
				ConditionIndex  int    `json:"conditionIndex"`
				ConditionTypeID string `json:"conditionTypeId"`
				Operator        string `json:"operator"`
				Value           string `json:"value"`
			} `json:"conditions"`
			ID       string `json:"id"`
			Name     string `json:"name"`
			Operator string `json:"operator"`
		} `json:"constraints"`
		ID            string `json:"id"`
		Name          string `json:"name"`
		Notifications struct {
			JiraNotifications    []interface{} `json:"jiraNotifications"`
			RoleNotifications    []interface{} `json:"roleNotifications"`
			UserNotifications    []interface{} `json:"userNotifications"`
			WebhookNotifications []interface{} `json:"webhookNotifications"`
		} `json:"notifications"`
		OwnerID                              string `json:"ownerId"`
		PolicyViolationGrandfatheringAllowed bool   `json:"policyViolationGrandfatheringAllowed"`
		ThreatLevel                          int    `json:"threatLevel"`
	} `json:"policies"`
	LicenseThreatGroups []struct {
		ID                        string `json:"id"`
		Name                      string `json:"name"`
		NameLowercaseNoWhitespace string `json:"nameLowercaseNoWhitespace"`
		OwnerID                   string `json:"ownerId"`
		ThreatLevel               int    `json:"threatLevel"`
	} `json:"licenseThreatGroups"`
	LicenseThreatGroupLicenses []struct {
		ID                   string `json:"id"`
		LicenseID            string `json:"licenseId"`
		LicenseThreatGroupID string `json:"licenseThreatGroupId"`
		OwnerID              string `json:"ownerId"`
	} `json:"licenseThreatGroupLicenses"`
	Labels []struct {
		Color          string `json:"color"`
		Description    string `json:"description"`
		ID             string `json:"id"`
		Label          string `json:"label"`
		LabelLowercase string `json:"labelLowercase"`
		OwnerID        string `json:"ownerId"`
	} `json:"labels"`
	PolicyTags []struct {
		ID       string `json:"id"`
		PolicyID string `json:"policyId"`
		TagID    string `json:"tagId"`
	} `json:"policyTags"`
	Tags []struct {
		Color                     string `json:"color"`
		Description               string `json:"description"`
		ID                        string `json:"id"`
		Name                      string `json:"name"`
		NameLowercaseNoWhitespace string `json:"nameLowercaseNoWhitespace"`
		OrganizationID            string `json:"organizationId"`
	} `json:"tags"`
}

// ExportPolicies returns the policies of the indicated IQ server
func ExportPolicies(iq publiciq.IQ) (p IQPolicySet, err error) {
	endpoint := fmt.Sprintf(restPolicyExportPrivate, "ROOT_ORGANIZATION_ID")

	body, _, err := FromPublic(iq).Get(endpoint)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &p)

	return
}

// ImportPolicies imports the given policies
func ImportPolicies(iq publiciq.IQ, file io.Reader) error {

	piq := FromPublic(iq)

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	fw, err := w.CreateFormFile("file", "file")
	if err != nil {
		return err
	}

	_, err = io.Copy(fw, file)

	if err := w.Close(); err != nil {
		return err
	}

	endpoint := fmt.Sprintf(restPolicyImportPrivate, "ROOT_ORGANIZATION_ID")
	req, err := piq.NewRequest("POST", endpoint, &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if err != nil {
		return err
	}

	_, _, err = piq.Do(req)

	return err
}
