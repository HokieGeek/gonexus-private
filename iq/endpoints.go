package privateiq

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const iqRestOrganizationPrivate = "rest/organization/%s"
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
	endpoint := fmt.Sprintf(iqRestOrganizationPrivate, organizationID)

	resp, err := FromPublic(iq).Del(endpoint)
	if err != nil && resp.StatusCode != http.StatusNoContent {
		return err
	}

	return nil
}

// EvaluateComponentsAsFirewall evaluates the list of components using Root Organization only
func EvaluateComponentsAsFirewall(iq publiciq.IQ, components []publiciq.Component) (eval *publiciq.Evaluation, err error) {
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
	endpoint := fmt.Sprintf(iqRestFirewallPrivate, repoid)

	body, _, err := FromPublic(iq).Get(endpoint)
	if err = json.Unmarshal(body, &c); err != nil {
		return
	}

	return
}

/*
// Install license
curl --verbose \
     --user ${user_pwd} \
     --cookie-jar ${cookies} --cookie ${cookies} \
     --header "X-CSRF-TOKEN: $(awk '/CLM-CSRF-TOKEN/ { print $NF }' ${cookies})" \
     --form "file=@${license}" \
     "http://${iq_host}/rest/product/license"

// Support Zip
curl --verbose \
     --user ${user_pwd} \
     --cookie-jar ${cookies} --cookie ${cookies} \
     --header "X-CSRF-TOKEN: $(awk '/CLM-CSRF-TOKEN/ { print $NF }' ${cookies})" \
     -o ./nexus-iq-support_$(date +%Y%m%d-%H%M).zip \
     "${iq_host}/rest/support?noLimit=true"

// Export policiet
curl --verbose \
     --user ${user_pwd} \
     --cookie-jar ${cookies} --cookie ${cookies} \
     --header "X-CSRF-TOKEN: $(awk '/CLM-CSRF-TOKEN/ { print $NF }' ${cookies})" \
     "http://${iq_host}/rest/policy/organization/ROOT_ORGANIZATION_ID/export" \
     | tee policies_$(date +%Y%m%d%H%M).json
*/
