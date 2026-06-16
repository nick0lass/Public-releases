# Security Advisory: Multiple Vulnerabilities in TestReach Desktop Application

**Advisory ID:** ADV-2026-001
**CVE IDs:** CVE-2026-36487, CVE-2026-36488, CVE-2026-36489, CVE-2026-36490, CVE-2026-36491, CVE-2026-36492
**Vendor:** TestReach Ltd
**Product:** TestReach Desktop Application
**Affected Versions:** 6.2.0 and prior
**Disclosure Date:** 16 June 2026
**Researchers:** Nicholas Ineson (Forefront IT Security Services Ltd), Mick Dunne (Independent Researcher)

---

## Summary

The TestReach Desktop Application is an Electron-based thick client used to provide a locked-down environment for proctored online examinations. During an independent security assessment, six vulnerabilities were identified in version 6.2.0. The application's security controls are enforced entirely client-side, with no server-side integrity verification or client attestation. As a result, the lockdown and anti-tampering controls can be defeated by a standard user account without administrator privileges.

The vendor was notified on 18 February 2026 and did not respond within the 90-day coordinated disclosure window. Six CVE identifiers have been assigned for the findings below.

---

## Vulnerabilities

### CVE-2026-36487 — Active Debug Code in Production Build
**CWE-489 (Active Debug Code) · CVSS 3.1 Base 8.4 (High)**

The production build retains fully functional developer/debug functionality, suppressed only by a client-side boolean value. No build-time stripping or removal is performed, so the debug code is present in every installed copy. When enabled, it exposes developer tooling and removes lockdown controls, while the session continues to appear normal to the remote proctor.

### CVE-2026-36488 — Insecure Electron Configuration (Remote Code Execution)
**CWE-693 (Protection Mechanism Failure) · CVSS 3.1 Base 8.6 (High)**

The Electron `BrowserWindow` is configured with `nodeIntegration` enabled and `contextIsolation` disabled, alongside other deprecated and insecure options. This grants renderer content access to the Node.js runtime, including operating-system command execution, filesystem access, and network access. The application archive containing the source code is protected only by a filesystem read-only attribute, with no code signing or integrity verification, allowing modification by a standard user. Electron's own documentation identifies this as the highest-risk configuration for applications loading remote content.

### CVE-2026-36489 — TLS Certificate Validation Disabled
**CWE-295 (Improper Certificate Validation) · CVSS 3.1 Base 8.1 (High)**

The application launches the runtime with certificate-error handling disabled unconditionally, disabling all TLS/SSL certificate validation for every network connection. The application will accept any certificate, including expired, self-signed, or forged certificates, with no warning. An attacker positioned on the same network as a candidate can perform man-in-the-middle interception and modification of all traffic, including credentials, session tokens, examination content, and candidate responses.

### CVE-2026-36490 — Hard-coded Kiosk Exit Password
**CWE-798 (Use of Hard-coded Credentials) · CVSS 3.1 Base 8.4 (High)**

The application source contains a hard-coded plaintext password used to exit the kiosk-mode lockdown. The credential is identical across all installations and cannot be changed by exam providers or administrators. It is recoverable from the application archive, which lacks integrity protection.

### CVE-2026-36491 — Unauthenticated API Endpoint Exposing OAuth Tokens
**CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) · CVSS 3.1 Base 5.3 (Medium)**

A server-side configuration endpoint returns sensitive application configuration in plaintext JSON to unauthenticated clients, including server-side OAuth tokens, storage bucket paths, and third-party application identifiers. No authentication, session token, API key, or network restriction is enforced. Exposed credentials of this type could permit authentication to third-party services on behalf of the application's service account, and the infrastructure identifiers provide reconnaissance value.

### CVE-2026-36492 — Same-Origin Policy Bypass (WebView)
**CWE-346 (Origin Validation Error) · CVSS 3.1 Base 8.6 (High)**

The examination WebView is configured with web security disabled, removing the same-origin policy. JavaScript executing within the exam frame can issue unrestricted cross-origin requests to arbitrary external servers. Combined with the Node.js integration described in CVE-2026-36488, this permits exfiltration of examination content and local filesystem access from within the exam session, with no visible change to the interface.

---

## Impact

The combined effect of these vulnerabilities is that the examination lockdown is not a reliable security boundary. A candidate with control of their own machine can disable lockdown controls, execute arbitrary code, intercept or modify exam traffic, and exfiltrate examination content, while the proctoring session and server observe an apparently normal client. Because the server performs no client integrity verification, a modified client is indistinguishable from a legitimate one.

---

## Remediation

Vendor-side remediation should include:

- Remove hard-coded credentials; use server-generated, time-limited tokens.
- Remove the unconditional certificate-error suppression and implement proper TLS validation.
- Remove the web-security override and enforce origin restrictions server-side.
- Strip debug/developer functionality from production builds.
- Remove server-side credentials from client-facing API responses and require authentication on configuration endpoints.
- Harden the Electron configuration: enable `contextIsolation`, disable `nodeIntegration`, remove deprecated modules, and use a `contextBridge` for IPC.
- Implement application-archive integrity verification (signing and startup hash validation).
- Add server-side client attestation and validate proctoring controls server-side rather than relying on client-side enforcement.
- Update outdated dependencies and the Electron framework.

---

## Disclosure Timeline

- **18 February 2026** — Vendor notified via responsible disclosure.
- **February–May 2026** — Multiple follow-up contacts; no vendor response.
- **19 May 2026** — 90-day coordinated disclosure window expired with no vendor response.
- **[assignment date]** — CVE identifiers CVE-2026-36487 to CVE-2026-36492 assigned.
- **16 June 2026** — Public advisory released.

---

## Credit

Research by Nicholas Ineson, Director, Forefront IT Security Services Ltd, and Mick Dunne, Independent Researcher.

## References

- Vendor: https://www.testreach.com
- Forefront IT Security Services: https://forefrontitsecurityservices.co.uk
