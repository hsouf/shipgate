// Package audit emits structured allow/deny events so every decision is
// traceable to an image, commit, policy version and reason.
//
// TODO(#17): optional Slack / generic webhook notification on would-deny.
package audit

import (
	"context"
	"io"
	"log/slog"
)

// Logger writes JSON audit events.
type Logger struct{ l *slog.Logger }

// NewLogger returns a JSON audit logger writing to w.
func NewLogger(w io.Writer) *Logger {
	return &Logger{l: slog.New(slog.NewJSONHandler(w, nil))}
}

// Event is one gate decision as seen by a caller.
type Event struct {
	Source   string // "webhook", "cli"
	Image    string
	Commit   string
	Allowed  bool // the gate's real decision
	Enforced bool // whether the caller acted on a deny
	Reason   string
	Request  string // e.g. admission request UID
}

// Record logs an event. Would-deny in audit mode is logged at WARN.
func (a *Logger) Record(e Event) {
	level := slog.LevelInfo
	msg := "allow"
	switch {
	case !e.Allowed && e.Enforced:
		level, msg = slog.LevelError, "deny"
	case !e.Allowed:
		level, msg = slog.LevelWarn, "would-deny (audit mode)"
	}
	a.l.Log(context.Background(), level, msg,
		"source", e.Source, "image", e.Image, "commit", e.Commit,
		"allowed", e.Allowed, "enforced", e.Enforced, "reason", e.Reason, "request", e.Request)
}
