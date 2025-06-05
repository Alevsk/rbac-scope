package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewServer(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Fatal("NewServer() returned nil")
	}
	if s.router == nil {
		t.Error("NewServer() did not initialize router")
	}
	// We can also test if the route is registered by making a request
	// to the health check endpoint using the server's router.
	req, _ := http.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestHealthCheckHandler(t *testing.T) {
	s := NewServer() // Server setup includes routes
	req, err := http.NewRequest("GET", "/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	// Directly call the handler function, or serve via router
	// s.healthCheck(rr, req) // Option 1: Direct call
	s.router.ServeHTTP(rr, req) // Option 2: Serve via router (tests routing too)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("healthCheck handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := `{"status":"healthy"}` + "\n" // json.Encoder adds a newline
	if rr.Body.String() != expected {
		t.Errorf("healthCheck handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

// mockResponseWriter to simulate errors in json.Encode
type mockResponseWriter struct {
	httptest.ResponseRecorder
	failWrite bool // if true, Write will return an error
}

// WriteHeader is needed to satisfy http.ResponseWriter, but we mostly care about the recorder's Code.
// We can capture it if needed, but for this test, ResponseRecorder's default behavior is fine.
func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.ResponseRecorder.WriteHeader(statusCode)
}

// Write simulates a failure if m.failWrite is true
func (m *mockResponseWriter) Write(body []byte) (int, error) {
	if m.failWrite {
		return 0, http.ErrHandlerTimeout // Simulate some error
	}
	return m.ResponseRecorder.Write(body)
}

func TestHealthCheckHandler_EncodingError(t *testing.T) {
	s := NewServer()
	req, err := http.NewRequest("GET", "/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Use the custom mockResponseWriter
	// We need to initialize it properly.
	// The ResponseRecorder part will store the status code.
	rr := &mockResponseWriter{ResponseRecorder: *httptest.NewRecorder(), failWrite: true}

	// Call the handler function directly as we are testing its internal error handling
	s.healthCheck(rr, req)

	// Check if the status code was set to InternalServerError
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("healthCheck handler with encoding error returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}
	// We don't check the body because the write was supposed to fail.
}
