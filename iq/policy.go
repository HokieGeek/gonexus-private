package privateiq

import (
	"encoding/json"
	"fmt"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const iqRestPolicyPrivate = "rest/policy/organization/%s/export"

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
	endpoint := fmt.Sprintf(iqRestPolicyPrivate, "ROOT_ORGANIZATION_ID")

	body, _, err := FromPublic(iq).Get(endpoint)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &p)

	return
}
