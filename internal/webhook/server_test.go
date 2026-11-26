package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hsouf/shipgate/internal/audit"
	"github.com/hsouf/shipgate/internal/gate"
)

type denyAll struct{}

func (denyAll) Verify(_ context.Context, r gate.Request) gate.Decision {
	return gate.Decision{Image: r.Image, Allowed: false, Reason: "policy: not verified"}
}

const deployment = `{
 "apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",
 "request":{"uid":"123","kind":{"group":"apps","version":"v1","kind":"Deployment"},
  "object":{"spec":{"template":{"spec":{"containers":[{"image":"app@sha256:abc"}]}}}}}}`

func post(t *testing.T, enforce bool) admissionReview {
	t.Helper()
	s := NewServer(Config{Enforce: enforce}, denyAll{}, audit.NewLogger(io.Discard))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewBufferString(deployment)))
	var out admissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAuditModeAdmitsWithWarning(t *testing.T) {
	out := post(t, false)
	if !out.Response.Allowed || out.Response.UID != "123" {
		t.Fatalf("audit mode must admit: %+v", out.Response)
	}
	if len(out.Response.Warnings) == 0 || !strings.Contains(out.Response.Warnings[0], "would deny") {
		t.Fatalf("expected would-deny warning, got %+v", out.Response.Warnings)
	}
}

func TestEnforceModeDenies(t *testing.T) {
	out := post(t, true)
	if out.Response.Allowed || out.Response.Status == nil || out.Response.Status.Code != 403 {
		t.Fatalf("enforce mode must deny: %+v", out.Response)
	}
}

func TestImagesFromCronJob(t *testing.T) {
	raw := []byte(`{"spec":{"jobTemplate":{"spec":{"template":{"spec":{
		"initContainers":[{"image":"init@sha256:1"}],"containers":[{"image":"main@sha256:2"}]}}}}}}`)
	imgs, err := imagesFrom("CronJob", raw)
	if err != nil || len(imgs) != 2 {
		t.Fatalf("got %v, %v", imgs, err)
	}
}
