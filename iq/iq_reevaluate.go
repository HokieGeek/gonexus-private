package privateiq

import (
	"fmt"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const restReportReevaluate = "rest/report/%s/%s/reevaluatePolicy"

// ReevaluateReportByID hits the re-eval button on the specified report
func ReevaluateReportByID(iq publiciq.IQ, appID, ReportID string) error {
	endpoint := fmt.Sprintf(restReportReevaluate, appID, ReportID)
	_, _, err := FromPublic(iq).Post(endpoint, nil)
	return err
}

// ReevaluateReportByApp hits the re-eval button
func ReevaluateReportByApp(iq publiciq.IQ, appID, stage string) error {
	info, err := publiciq.GetReportInfoByAppIDStage(iq, appID, stage)
	if err != nil {
		return fmt.Errorf("did not find report for '%s' at '%s' build stage: %v", appID, stage, err)
	}

	return ReevaluateReportByID(iq, appID, info.ReportID())
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
