// Package webhook serves a Kubernetes ValidatingAdmissionWebhook that runs
// every container image through the gate.
//
// Audit mode (default) always admits and logs would-deny decisions, so teams
// can find every deploy path before blocking anything. --enforce denies.
//
// TODO(#16): Helm chart polish, cert management, latency budget + timeouts,
// caching of decisions per digest.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hsouf/shipgate/internal/audit"
	"github.com/hsouf/shipgate/internal/gate"
)

// Config for the webhook server.
type Config struct {
	Addr        string
	TLSCertFile string
	TLSKeyFile  string
	Enforce     bool
}

// Verifier is the subset of gate.Verifier the webhook needs.
type Verifier interface {
	Verify(ctx context.Context, req gate.Request) gate.Decision
}

// Server is the admission webhook.
type Server struct {
	cfg   Config
	v     Verifier
	audit *audit.Logger
}

// NewServer builds a Server.
func NewServer(cfg Config, v Verifier, a *audit.Logger) *Server {
	return &Server{cfg: cfg, v: v, audit: a}
}

// Handler returns the HTTP handler (exposed for tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", s.validate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// ListenAndServe serves TLS until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
		return errors.New("--tls-cert and --tls-key are required: Kubernetes only calls webhooks over TLS")
	}
	srv := &http.Server{Addr: s.cfg.Addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var review admissionReview
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&review); err != nil || review.Request == nil {
		http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
		return
	}
	req := review.Request
	resp := &admissionResponse{UID: req.UID, Allowed: true}

	images, err := imagesFrom(req.Kind.Kind, req.Object)
	if err != nil {
		s.respond(w, review, s.decide(resp, req.UID, []gate.Decision{{
			Allowed: false, Reason: "could not parse object: " + err.Error(),
		}}))
		return
	}

	decisions := make([]gate.Decision, 0, len(images))
	for _, img := range images {
		decisions = append(decisions, s.v.Verify(r.Context(), gate.Request{Image: img}))
	}
	s.respond(w, review, s.decide(resp, req.UID, decisions))
}

// decide folds per-image decisions into one admission response, applying
// audit vs enforce mode. The gate's own decision is always logged as-is.
func (s *Server) decide(resp *admissionResponse, uid string, ds []gate.Decision) *admissionResponse {
	var denied []string
	for _, d := range ds {
		s.audit.Record(audit.Event{
			Source: "webhook", Image: d.Image, Commit: d.Commit,
			Allowed: d.Allowed, Enforced: s.cfg.Enforce, Reason: d.Reason, Request: uid,
		})
		if !d.Allowed {
			denied = append(denied, fmt.Sprintf("%s: %s", d.Image, d.Reason))
		}
	}
	if len(denied) == 0 {
		return resp
	}
	msg := "shipgate: " + strings.Join(denied, "; ")
	if s.cfg.Enforce {
		resp.Allowed = false
		resp.Status = &status{Code: http.StatusForbidden, Message: msg}
	} else {
		resp.Warnings = append(resp.Warnings, "[audit mode] would deny: "+msg)
	}
	return resp
}

func (s *Server) respond(w http.ResponseWriter, in admissionReview, resp *admissionResponse) {
	out := admissionReview{APIVersion: in.APIVersion, Kind: in.Kind, Response: resp}
	if out.APIVersion == "" {
		out.APIVersion = "admission.k8s.io/v1"
	}
	if out.Kind == "" {
		out.Kind = "AdmissionReview"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
