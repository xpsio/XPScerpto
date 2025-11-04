# Releases Guide

1. Create a new release (e.g., v1.0.0) from the `main` branch.
2. Upload artifacts:
   - XPScerpto_v9_FINAL_MAX_publishable.tar.gz
   - XPScerpto_v9_FINAL_MAX_publishable.zip
   - SHA256SUMS.txt
3. Paste the contents of RELEASE_NOTES.md as the description.

## Verify checksums
**Linux/macOS:**
```bash
shasum -a 256 XPScerpto_v9_FINAL_MAX_publishable.tar.gz XPScerpto_v9_FINAL_MAX_publishable.zip
```
**Windows (PowerShell):**
```powershell
Get-FileHash XPScerpto_v9_FINAL_MAX_publishable.zip -Algorithm SHA256
Get-FileHash XPScerpto_v9_FINAL_MAX_publishable.tar.gz -Algorithm SHA256
```

