package privateiq

import (
	"bytes"
	"encoding/json"

	nexusiq "github.com/sonatype-nexus-community/gonexus/iq"
	// nexusiq "github.com/sonatype-nexus-community/gonexus/iq"
)

// POST: http://iq:8070/rest/label/organization/ROOT_ORGANIZATION_ID?timestamp=1576003030777
const restLabelComponentOrg = "rest/label/organization/%s"

// req: {"id":null,"ownerId":null,"label":"foo","labelLowercase":null,"color":"orange","description":"bar"}
// res: {"id":"87068951ec494e79842b0cef4294b371","ownerId":"ROOT_ORGANIZATION_ID","label":"foo","labelLowercase":"foo","description":"bar","color":"orange"}

type IqComponentLabel struct {
	ID             string `json:"id,omitempty"`
	OwnerID        string `json:"ownerId,omitempty"`
	Label          string `json:"label"`
	LabelLowercase string `json:"labelLowercase,omitempty"`
	Description    string `json:"description,omitempty"`
	Color          string `json:"color"`
}

func GetAllComponentLabels(iq nexusiq.IQ) ([]IqComponentLabel, error) {
	body, _, err := FromPublic(iq).Get(restLabelComponentOrg)
	if err != nil {
		return nil, err
	}

	var labels []IqComponentLabel
	err = json.Unmarshal(body, &labels)
	if err != nil {
		return nil, err
	}

	return labels, nil
}

func CreateComponentLabel(iq nexusiq.IQ, organization, label, description, color string) error {
	req := &IqComponentLabel{OwnerID: organization, Label: label, Description: description, Color: color}
	buf, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_, _, err = FromPublic(iq).Post(restLabelComponentOrg, bytes.NewBuffer(buf))
	return err
}

// func DeleteComponentLabel()
