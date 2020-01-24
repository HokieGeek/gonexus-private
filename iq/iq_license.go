package privateiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const restLicense = "rest/product/license"

type NexusLicense struct {
	ProductEdition            string      `json:"productEdition"`
	Fingerprint               string      `json:"fingerprint"`
	ExpiryTimestamp           int64       `json:"expiryTimestamp"`
	LicensedUsersToDisplay    int64       `json:"licensedUsersToDisplay"`
	ApplicationLimitToDisplay interface{} `json:"applicationLimitToDisplay"`
	FirewallUsersToDisplay    int64       `json:"firewallUsersToDisplay"`
	ContactName               string      `json:"contactName"`
	ContactCompany            string      `json:"contactCompany"`
	ContactEmail              string      `json:"contactEmail"`
	Products                  []string    `json:"products"`
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
	if err != nil {
		return fmt.Errorf("could not create license request: %v", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	if _, resp, err := piq.Do(req); err != nil && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("could not send license request: %v", err)
	}

	return nil
}

func LicenseInfo(iq publiciq.IQ) (license NexusLicense, err error) {
	body, _, err := FromPublic(iq).Get(restLicense)
	if err = json.Unmarshal(body, &license); err != nil {
		return
	}
	return
}
