package webhook

import "encoding/json"

// Minimal subset of Kubernetes admission/v1 types. Kept local on purpose so
// the binary does not pull in k8s.io/* for v0.1. Swap for k8s.io/api if the
// surface grows.

type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID    string           `json:"uid"`
	Kind   groupVersionKind `json:"kind"`
	Object json.RawMessage  `json:"object"`
}

type groupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

type admissionResponse struct {
	UID      string   `json:"uid"`
	Allowed  bool     `json:"allowed"`
	Status   *status  `json:"status,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type status struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type container struct {
	Image string `json:"image"`
}

type podSpec struct {
	InitContainers      []container `json:"initContainers"`
	Containers          []container `json:"containers"`
	EphemeralContainers []container `json:"ephemeralContainers"`
}

// imagesFrom extracts every container image from a Pod or a workload
// controller (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob).
func imagesFrom(kind string, raw json.RawMessage) ([]string, error) {
	var spec podSpec
	switch kind {
	case "Pod":
		var o struct {
			Spec podSpec `json:"spec"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec
	case "CronJob":
		var o struct {
			Spec struct {
				JobTemplate struct {
					Spec struct {
						Template struct {
							Spec podSpec `json:"spec"`
						} `json:"template"`
					} `json:"spec"`
				} `json:"jobTemplate"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.JobTemplate.Spec.Template.Spec
	default:
		var o struct {
			Spec struct {
				Template struct {
					Spec podSpec `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		spec = o.Spec.Template.Spec
	}
	var out []string
	for _, group := range [][]container{spec.InitContainers, spec.Containers, spec.EphemeralContainers} {
		for _, c := range group {
			if c.Image != "" {
				out = append(out, c.Image)
			}
		}
	}
	return out, nil
}
