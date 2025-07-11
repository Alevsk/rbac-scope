package resolver

import (
	"net/http"
	"testing"
)

func TestMockHTTPClient(t *testing.T) {
	mock := newMockHTTPClient()
	mock.addResponse("http://example.com/ok", http.StatusOK, "ok")
	client := mock.GetClient()

	req, _ := http.NewRequest("GET", "http://example.com/ok", nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 ok, got %v", err)
	}

	req2, _ := http.NewRequest("GET", "http://example.com/missing", nil)
	resp2, err := client.Do(req2)
	if err != nil || resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %v %d", err, resp2.StatusCode)
	}
}
