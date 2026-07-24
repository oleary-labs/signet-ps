package server

import (
	"net/http"

	"signet.dev/ps/internal/consent"
)

// approvePage is the human approval surface (GET /approve/{code}). It is
// curl-grade in v0: a JSON description of what is being approved.
//
//   - Routine tier: the click IS the approval — hitting this URL approves the
//     request (the PSA is the authority; the click is UX, per the tier model).
//   - Elevated tier: a click cannot move it. We return the ApprovalDigest the
//     root must sign and point at POST /approve/{code}/signature (I3).
func (s *Server) approvePage(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	req, err := s.pending.ByCode(code)
	if err != nil {
		writeErr(w, 404, "unknown_code", err)
		return
	}

	if req.Tier == consent.TierElevated {
		digest, derr := consent.ApprovalDigest(req, s.cfg.ChainID, s.cfg.RegistryAddr)
		if derr != nil {
			writeErr(w, 500, "digest_error", derr)
			return
		}
		writeJSON(w, 200, map[string]any{
			"tier":     "elevated",
			"message":  "this action exceeds the PSA step-up threshold; a root signature is required",
			"request":  req,
			"digest":   hexStr(digest[:]),
			"sign_url": s.cfg.IssuerURL + "/approve/" + code + "/signature",
		})
		return
	}

	if err := s.pending.ApproveRoutine(code); err != nil {
		writeErr(w, 409, "cannot_approve", err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "approved", "code": code, "tier": "routine"})
}
