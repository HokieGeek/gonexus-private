# gonexus-private

Provides a go library for connecting to, and interacting with, the ***private APIs*** of Sonatype Nexus application such as Nexus Repository Manager and Nexus IQ Server.

Specifically, it wraps around [github.com/sonatype-nexus-community/gonexus](//github.com/sonatype-nexus-community/gonexus) to add functionality using private APIs

## Organization of the library
The library is broken into two packages. One for each application

### nexusiq

Create a connection to an instance of Nexus IQ Server

Example:
```go
import (
	"github.com/hokiegeek/gonexus-private/iq"
	"github.com/sonatype-nexus-community/gonexus/iq"
)

func main() {
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

	// Delete that organization using the private API
	if err := privateiq.DeleteOrganization(iq, orgID); err != nil {
		panic(err)
	}
}
```

### nexusrm

TODO... maybe
