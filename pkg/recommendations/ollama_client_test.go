package recommendations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCallOllama_Success(t *testing.T) {
	resp := `{"response":"{\"recommendations\":[{\"title\":\"t\",\"priority\":1,\"rationale\":\"r\",\"actions\":[\"a\"],\"related_rules\":[\"R1\"]}]}"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
	defer ts.Close()

	ctx := context.Background()
	recs, err := CallOllama(ctx, ts.URL, "any-model", "prompt", 3*time.Second)
	if err != nil {
		t.Fatalf("CallOllama error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
}
