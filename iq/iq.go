package privateiq

import (
	"io"
	"net/http"

	nexus "github.com/sonatype-nexus-community/gonexus"
	publiciq "github.com/sonatype-nexus-community/gonexus/iq"
)

const restSessionPrivate = "rest/user/session"

// Defines a new IQ instance which provides overrides to transparently allow access to private APIs
type privateiq struct {
	nexus.DefaultClient
	// publiciq.IQ
	pub publiciq.IQ
}

// NewRequest creates an http.Request object with private session
func (iq privateiq) NewRequest(method, endpoint string, payload io.Reader) (*http.Request, error) {
	req, err := iq.pub.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, err
	}

	_, resp, err := iq.pub.Get(restSessionPrivate)
	if err != nil {
		return nil, err
	}

	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
		if cookie.Name == "CLM-CSRF-TOKEN" {
			req.Header.Add("X-CSRF-TOKEN", cookie.Value)
		}
	}

	return req, nil
}

func (iq privateiq) http(method, endpoint string, payload io.Reader) ([]byte, *http.Response, error) {
	request, err := iq.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, nil, err
	}

	return iq.Do(request)
}

// Get performs an HTTP GET against the indicated endpoint
func (iq privateiq) Get(endpoint string) ([]byte, *http.Response, error) {
	return iq.http(http.MethodGet, endpoint, nil)
}

// Post performs an HTTP POST against the indicated endpoint
func (iq privateiq) Post(endpoint string, payload io.Reader) ([]byte, *http.Response, error) {
	return iq.http(http.MethodPost, endpoint, payload)
}

// Put performs an HTTP PUT against the indicated endpoint
func (iq privateiq) Put(endpoint string, payload io.Reader) ([]byte, *http.Response, error) {
	return iq.http(http.MethodPut, endpoint, payload)
}

// Del performs an HTTP DELETE against the indicated endpoint
func (iq privateiq) Del(endpoint string) (resp *http.Response, err error) {
	_, resp, err = iq.http(http.MethodDelete, endpoint, nil)
	return
}

// FromPublic wraps a privateiq instance around a public one
func FromPublic(iq publiciq.IQ) publiciq.IQ {
	priv := new(privateiq)
	priv.pub = iq
	priv.Host = iq.Info().Host
	priv.Username = iq.Info().Username
	priv.Password = iq.Info().Password
	return priv
}
