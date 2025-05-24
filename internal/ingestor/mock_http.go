package ingestor

import (
	"io"
	"net/http"
	"strings"
)

// mockHTTPClient is a mock HTTP client for testing
type mockHTTPClient struct {
	responses map[string]mockResponse
}

func (m *mockHTTPClient) GetClient() *http.Client {
	return &http.Client{Transport: m}
}

type mockResponse struct {
	statusCode int
	body       string
}

func newMockHTTPClient() *mockHTTPClient {
	return &mockHTTPClient{
		responses: make(map[string]mockResponse),
	}
}

func (m *mockHTTPClient) addResponse(url string, statusCode int, body string) {
	m.responses[url] = mockResponse{
		statusCode: statusCode,
		body:       body,
	}
}

func (m *mockHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, ok := m.responses[req.URL.String()]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("not found")),
			Request:    req,
		}, nil
	}

	return &http.Response{
		StatusCode: resp.statusCode,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Request:    req,
	}, nil
}
