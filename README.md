# gonexus-private

Provides a go library for connecting to, and interacting with, the ***private APIs*** of Sonatype Nexus application such as Nexus Repository Manager and Nexus IQ Server.

Specifically, it wraps around [github.com/hokiegeek/gonexus](//github.com/hokiegeek/gonexus) to add functionality using private APIs

## Organization of the library
The library is broken into two packages. One for each application

### nexusiq

Create a connection to an instance of Nexus IQ Server
```go
import "github.com/hokiegeek/gonexus-private/iq"

iq, err := nexusiq.New("http://localhost:8070", "user", "password")
if err != nil {
    panic(err)
}
```

### nexusrm

TODO... maybe
