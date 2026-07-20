package audit

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStoreIsBoundedNewestFirstAndCopies(t *testing.T) {
	store := NewStore(2)
	for _, id := range []string{"one", "two", "three"} {
		store.Add(Trace{RequestID: id, Timestamp: time.Unix(0, 0), Detections: []Detection{{SecretType: "token"}}})
	}

	got := store.List()
	if len(got) != 2 || got[0].RequestID != "three" || got[1].RequestID != "two" {
		t.Fatalf("unexpected bounded trace order: %#v", got)
	}
	got[0].Detections[0].SecretType = "mutated"
	if store.List()[0].Detections[0].SecretType != "token" {
		t.Fatal("List returned mutable store-owned detection data")
	}
}

func TestHandlerContainsMetadataOnly(t *testing.T) {
	store := NewStore(4)
	store.Add(Trace{
		RequestID: "req_safe",
		Detections: []Detection{{
			SecretType:        "GitHub token",
			PlaceholderID:     "[[GH_PAT_A1B2C3D4]]",
			OriginalPrevented: true,
		}},
	})
	recorder := httptest.NewRecorder()
	store.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/audit", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, "GH_PAT_A1B2C3D4") || !strings.Contains(body, "original_prevented") {
		t.Fatalf("missing safe audit metadata: %s", body)
	}
	for _, forbidden := range []string{"request_body", "raw_secret", "secret_hash"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("audit response contains forbidden field %q", forbidden)
		}
	}
}
