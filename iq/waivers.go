package privateiq

/*
rest/policyWaiver/application/agileteam/component/37f4bb2af6ff8292fbd5

{"waiversByOwner":[{"ownerId":"agileteam","ownerName":"agileteam","ownerType":"application","waivers":[{"id":"da78aaac9f774518a5a143ab152d7663","hash":"37f4bb2af6ff8292fbd5","policyId":"0cac09264717402f93960fd9af89f058","ownerId":"agileteam","comment":"","createTime":1565707371130,"constraintFactsJson":null,"constraintFacts":null,"policyName":"Security-High"}]}]}

type ComponentWaivers struct {
	WaiversByOwner []WaiversByOwner `json:"waiversByOwner"`
}

type WaiversByOwner struct {
	OwnerID   string   `json:"ownerId"`
	OwnerName string   `json:"ownerName"`
	OwnerType string   `json:"ownerType"`
	Waivers   []Waiver `json:"waivers"`
}

type Waiver struct {
	ID                  string      `json:"id"`
	Hash                string      `json:"hash"`
	PolicyID            string      `json:"policyId"`
	OwnerID             string      `json:"ownerId"`
	Comment             string      `json:"comment"`
	CreateTime          int64       `json:"createTime"`
	ConstraintFactsJSON interface{} `json:"constraintFactsJson"`
	ConstraintFacts     interface{} `json:"constraintFacts"`
	PolicyName          string      `json:"policyName"`
}
*/
