package privateiq

import (
	"bytes"
	"io"
	"net/http"

	publiciq "github.com/hokiegeek/gonexus/iq"
)

const iqRestSessionPrivate = "rest/user/session"

// Defines a new IQ instance which provides overrides to transparently allow access to private APIs
type privateiq struct {
	publiciq.IQ
	pub *publiciq.IQ
}

// NewRequest creates an http.Request object with private session
func (iq privateiq) NewRequest(method, endpoint string, payload io.Reader) (*http.Request, error) {
	// req, err := iq.defaultServer.NewRequest(method, endpoint, payload)
	req, err := iq.pub.NewRequest(method, endpoint, payload)
	if err != nil {
		return nil, err
	}

	// _, resp, err := iq.defaultServer.Get(iqRestSessionPrivate)
	_, resp, err := iq.pub.Get(iqRestSessionPrivate)
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
	return iq.http("GET", endpoint, nil)
}

// Post performs an HTTP POST against the indicated endpoint
func (iq privateiq) Post(endpoint string, payload []byte) ([]byte, *http.Response, error) {
	return iq.http("POST", endpoint, bytes.NewBuffer(payload))
}

// Put performs an HTTP PUT against the indicated endpoint
func (iq privateiq) Put(endpoint string, payload []byte) ([]byte, *http.Response, error) {
	return iq.http("PUT", endpoint, bytes.NewBuffer(payload))
}

// Del performs an HTTP DELETE against the indicated endpoint
func (iq privateiq) Del(endpoint string) (resp *http.Response, err error) {
	_, resp, err = iq.http("DELETE", endpoint, nil)
	return
}

// Wraps a privateiq instance around a public one
func fromPublic(iq *publiciq.IQ) *privateiq {
	priv := new(privateiq)
	priv.pub = iq
	priv.Host = iq.Host
	priv.Username = iq.Username
	priv.Password = iq.Password
	return priv
}
