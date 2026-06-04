# Forefront Public Security Releases

Public security research write-ups from [Forefront IT Security Services](https://forefrontitsecurityservices.co.uk), published after coordinated disclosure and CVE assignment.

Research by **Nicholas Ineson**, Director of Forefront IT Security Services, and **Mick Dunne**, Independent Researcher.

---

## Releases

### ADV-2026-001 — Breaking Out of a "Secure" Exam Application

A complete thick client assessment of an Electron-based desktop exam proctoring application. Every security control was defeated with standard developer tools and no administrator privileges. Six CVEs were assigned: **CVE-2026-36487 to CVE-2026-36492**.

- [Read the full write-up](ADV-2026-001/Breaking%20Out%20of%20a%20%22Secure%22%20Exam%20Application%3A%20A%20Complete%20Thick%20Client%20Assessment%20Guide.md)

| CVE | CWE | Issue |
|-----|-----|-------|
| CVE-2026-36487 | CWE-489 | Active debug code in production build |
| CVE-2026-36488 | CWE-693 | Insecure Electron configuration (RCE) |
| CVE-2026-36489 | CWE-295 | TLS certificate validation disabled |
| CVE-2026-36490 | CWE-798 | Hard-coded kiosk exit password |
| CVE-2026-36491 | CWE-200 | Unauthenticated API exposing OAuth tokens |
| CVE-2026-36492 | CWE-346 | Same-origin policy bypass (WebView) |
