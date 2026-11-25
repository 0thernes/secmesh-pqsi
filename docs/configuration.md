# Configuration Reference (`docs/configuration.md`)

All runtime parameters are documented in `.env.example` and default to fail-closed loopback values.

| Variable | Default | Description |
| --- | --- | --- |
| `SECMESH_HOST` | `127.0.0.1` | Bind address for Guardian v2 HTTP/TCP listeners. Avoid `0.0.0.0` unless behind authenticated tunneling. |
| `SECMESH_HTTP_PORT` | `8790` | Loopback status endpoint (`/status`, returns zero key material). |
| `SECMESH_TCP_PORT` | `8791` | CW-128 authenticated mesh link endpoint. |
| `SECMESH_CORS_ORIGIN` | `http://127.0.0.1:8790` | Exact allowed CORS origin (`*` is rejected). |
| `SECMESH_MAX_FRAME_BYTES` | `65536` | Hard per-frame byte cap preventing memory-exhaustion DoS. |
| `SECMESH_NATIVE_BIN` | Auto-detected | Optional override path to `secmesh_core` / `secmesh_core.exe`. |
| `SECMESH_IT_PAD_FILE` | *(unset)* | Optional path to physical QRNG / pre-shared OTP pad activating unconditional PSI mode. |
