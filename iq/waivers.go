package privateiq

import (
	"encoding/json"
	"fmt"
	"sync"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const (
	// restWaiversForApplication = "rest/policyWaiver/application/agileteam/component/37f4bb2af6ff8292fbd5"
	restWaiversForApplication = "rest/policyWaiver/application/%s/component/%s"
)

/*
rest/policyWaiver/application/agileteam/component/37f4bb2af6ff8292fbd5

{"waiversByOwner":[{"ownerId":"agileteam","ownerName":"agileteam","ownerType":"application","waivers":[{"id":"da78aaac9f774518a5a143ab152d7663","hash":"37f4bb2af6ff8292fbd5","policyId":"0cac09264717402f93960fd9af89f058","ownerId":"agileteam","comment":"","createTime":1565707371130,"constraintFactsJson":null,"constraintFacts":null,"policyName":"Security-High"}]}]}
*/

type componentWaivers struct {
	WaiversByOwner []waiversByOwner `json:"waiversByOwner"`
}

type waiversByOwner struct {
	OwnerID   string       `json:"ownerId"`
	OwnerName string       `json:"ownerName"`
	OwnerType string       `json:"ownerType"`
	Waivers   []waiverJSON `json:"waivers"`
}

type waiverJSON struct {
	ID                  string `json:"id"`
	Hash                string `json:"hash"`
	PolicyID            string `json:"policyId"`
	OwnerID             string `json:"ownerId"`
	Comment             string `json:"comment"`
	CreateTime          int64  `json:"createTime"`
	ConstraintFactsJSON string `json:"constraintFactsJson"`
	ConstraintFacts     string `json:"constraintFacts"`
	PolicyName          string `json:"policyName"`
}

// Waiver encapsulates the information about a given waiver
type Waiver struct {
	ID                  string             `json:"id"`
	Component           publiciq.Component `json:"component"`
	PolicyID            string             `json:"policyId"`
	OwnerID             string             `json:"ownerId"`
	Comment             string             `json:"comment"`
	CreateTime          int64              `json:"createTime"`
	ConstraintFactsJSON string             `json:"constraintFactsJson"`
	ConstraintFacts     string             `json:"constraintFacts"`
	PolicyName          string             `json:"policyName"`
}

func waiverFromJSON(w waiverJSON, c publiciq.Component) Waiver {
	return Waiver{
		ID:                  w.ID,
		Component:           c,
		PolicyID:            w.PolicyID,
		OwnerID:             w.OwnerID,
		Comment:             w.Comment,
		CreateTime:          w.CreateTime,
		ConstraintFactsJSON: w.ConstraintFactsJSON,
		ConstraintFacts:     w.ConstraintFacts,
		PolicyName:          w.PolicyName,
	}
}

func waiversFromJSON(jsonWaivers []waiverJSON, c publiciq.Component) []Waiver {
	waivers := make([]Waiver, len(jsonWaivers))
	for i, w := range jsonWaivers {
		waivers[i] = waiverFromJSON(w, c)
	}
	return waivers
}

func getWaiversByComponentHash(iq publiciq.IQ, appID, hash string) ([]waiversByOwner, error) {
	body, _, err := FromPublic(iq).Get(fmt.Sprintf(restWaiversForApplication, appID, hash))
	if err != nil {
		return nil, err
	}

	var waivers componentWaivers
	err = json.Unmarshal(body, &waivers)

	return waivers.WaiversByOwner, err
}

// WaiversByAppIDStage returns the waivers associated with an application
func WaiversByAppIDStage(iq publiciq.IQ, appID, stage string) ([]Waiver, error) {
	report, err := publiciq.GetRawReportByAppID(iq, appID, stage)
	if err != nil {
		return nil, err
	}

	waivers := make([]Waiver, 0)

	for _, c := range report.Components {
		byOwner, _ := getWaiversByComponentHash(iq, appID, c.Hash)
		for _, o := range byOwner {
			waivers = append(waivers, waiversFromJSON(o.Waivers, c.Component)...)
		}
	}

	return waivers, nil
}

// WaiversByAppID returns the waivers associated with an application
func WaiversByAppID(iq publiciq.IQ, appID string) ([]Waiver, error) {
	waivers := make([]Waiver, 0)

	stages := []string{publiciq.StageBuild, publiciq.StageStageRelease, publiciq.StageRelease, publiciq.StageOperate}
	for _, s := range stages {
		stageWaivers, _ := WaiversByAppIDStage(iq, appID, s)
		waivers = append(waivers, stageWaivers...)
	}

	return waivers, nil
}

// Waivers returns the waivers for all applications in IQ
func Waivers(iq publiciq.IQ) ([]Waiver, error) {
	apps, err := publiciq.GetAllApplications(iq)
	if err != nil {
		return nil, err
	}

	waivers := make([]Waiver, 0)

	var mu sync.Mutex
	var wg sync.WaitGroup
	appIDs := make(chan string, 20)
	for w := 1; w <= 20; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range appIDs {
				appWaivers, _ := WaiversByAppID(iq, a)
				mu.Lock()
				waivers = append(waivers, appWaivers...)
				mu.Unlock()
			}
		}()
	}

	for _, a := range apps {
		appIDs <- a.PublicID
	}
	close(appIDs)

	wg.Wait()

	return waivers, nil
}
