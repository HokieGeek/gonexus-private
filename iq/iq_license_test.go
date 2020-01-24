package privateiq

import (
	"fmt"
	"testing"

	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

func TestLicenseInfo(t *testing.T) {
	tiq, err := publiciq.New("http://localhost:8070", "admin", "admin123")
	if err != nil {
		panic(err)
	}
	type args struct {
		iq publiciq.IQ
	}
	tests := []struct {
		name string
		args args
		// wantLicense NexusLicense
		wantErr bool
	}{
		{"test", args{tiq}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLicense, err := LicenseInfo(tt.args.iq)
			if (err != nil) != tt.wantErr {
				t.Errorf("LicenseInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// t.Logf("%q\n", gotLicensei.Fingerprint)
			fmt.Printf("%v\n", gotLicense.Fingerprint)
		})
	}
}
