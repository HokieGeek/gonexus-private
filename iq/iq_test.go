package privateiq

import (
	"time"

	"github.com/sonatype-nexus-community/gonexus/iq"
)

func ExampleDeleteOrganization() {
	// Define the IQ server instance
	iq, err := nexusiq.New("http://localhost:8070", "username", "password")
	if err != nil {
		panic(err)
	}

	// Create a new organization using the public API
	orgID, err := nexusiq.CreateOrganization(iq, "foobar")
	if err != nil {
		panic(err)
	}

	// Sleep long enough to verify that it exists in the GUI
	time.Sleep(15 * time.Second)

	// Delete that organization using the private API
	if err := DeleteOrganization(iq, orgID); err != nil {
		panic(err)
	}
}
