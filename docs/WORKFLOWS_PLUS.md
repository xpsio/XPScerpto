# WORKFLOWS_PLUS — XPScerpto Runbooks
**Version:** 1.0 • **Date:** 2025-11-03

## 1. Key Rotation — Checklist
- [ ] New key created and active
- [ ] Dual‑key decrypt window enabled
- [ ] Re‑encrypt at rest (optional) completed
- [ ] Metrics: zero uses of old key for ≥ grace period
- [ ] Old key retired → destroyed after retention

## 2. Emergency Revoke — Checklist
- [ ] Pause steady‑state ticks or force run orchestrator
- [ ] Mark key revoked; block usage
- [ ] Generate/activate replacement; prefer new for encrypt
- [ ] Re‑encrypt at rest expedited
- [ ] Incident report filed (audit, timelines, hashes)

## 3. Hot‑Patch — Checklist
- [ ] Capsule signature verified; publisher key‑pin OK
- [ ] API/ABI compatible; policy allow‑list OK
- [ ] KATs/micro‑benchmarks off‑path OK
- [ ] Stage new; drain old; route new
- [ ] Rollback on unhealthy metrics; audit preserved