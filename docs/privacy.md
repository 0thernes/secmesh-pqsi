# Privacy & Telemetry Policy (`docs/privacy.md`)

- **Zero Telemetry / Zero Phone-Home:** `secmesh-pqsi` collects, transmits, and stores **zero** analytics, crash reports, usage metrics, or personal identifiers.
- **Local-Only Execution:** All C11, Node.js, Python, Lean, and browser console (`app/index.html`) operations execute 100% locally offline (the sole optional network call in the entire repository is `python scripts/check_citations.py --online` when manually invoked to verify bibliography DOIs).
- **Zero Secret Persistence:** Ephemeral ML-KEM secret keys (`dk`), shared secrets (`ss`), and OTP pads are explicitly zeroized via `secmesh_secure_zero` in C11 and never serialized to `/status` or Rosette-Wire receipts.
