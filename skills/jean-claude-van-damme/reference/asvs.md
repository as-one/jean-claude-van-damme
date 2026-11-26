# ASVS 5.0 Requirements

Read only the chapters the target touches. Cite requirements as `ASVS 8.2.2 (L1)`. IDs from ASVS 4.0 do not carry over.

Checked against the official chapter files on 2026-11-26. **All Level 1 requirements are listed**, in abridged wording. Level 2 is a selection in V1, V6, V10, V13 and V16, and the other chapters list their Level 2 requirements. Level 3 is not listed: use the official standard for an L3 assessment.

This file summarizes the OWASP Application Security Verification Standard (https://github.com/OWASP/ASVS/tree/master/5.0/en) and is shared under CC BY-SA 4.0.

**Levels:** L1 is the minimum (about 20% of requirements). L2 is the target for most applications (about 70% cumulative). L3 adds the rest for the highest assurance.

## Contents

[V1](#v1-encoding-and-sanitization) · [V2](#v2-validation-and-business-logic) · [V3](#v3-web-frontend-security) · [V4](#v4-api-and-web-service) · [V5](#v5-file-handling) · [V6](#v6-authentication) · [V7](#v7-session-management) · [V8](#v8-authorization) · [V9](#v9-self-contained-tokens) · [V10](#v10-oauth-and-oidc) · [V11](#v11-cryptography) · [V12](#v12-secure-communication) · [V13](#v13-configuration) · [V14](#v14-data-protection) · [V15](#v15-secure-coding-and-architecture) · [V16](#v16-security-logging-and-error-handling) · [V17](#v17-webrtc)

## V1 Encoding and Sanitization

| ID | L | Requirement |
|---|---|---|
| 1.2.1 | 1 | Encode output for its HTTP, HTML, XML, CSS or header context |
| 1.2.2 | 1 | Encode data placed in URLs and permit only safe protocols |
| 1.2.3 | 1 | Encode data used to build JavaScript or JSON |
| 1.2.4 | 1 | Access databases with parameterized queries or an ORM |
| 1.2.5 | 1 | Protect OS calls against command injection |
| 1.3.1 | 1 | Sanitize user HTML from rich editors with a known library |
| 1.3.2 | 1 | Avoid `eval` and dynamic execution; sanitize input if unavoidable |
| 1.5.1 | 1 | Disable external entities in XML parsers |
| 1.1.1 | 2 | Decode input to canonical form once, where expected |
| 1.1.2 | 2 | Encode as the last step before the interpreter |
| 1.2.6 | 2 | Prevent LDAP injection |
| 1.2.9 | 2 | Escape special characters used in regular expressions |
| 1.3.3 | 2 | Restrict characters and length before dangerous contexts |
| 1.3.4 | 2 | Neutralize scripts and foreign content in user SVG |
| 1.3.5 | 2 | Sanitize or disable user Markdown, CSS, XSL and similar |
| 1.3.6 | 2 | Prevent SSRF with allowlists for protocol, domain, path and port |
| 1.3.7 | 2 | Never build templates from untrusted input |
| 1.3.8 | 2 | Sanitize JNDI queries and configure JNDI safely |
| 1.3.11 | 2 | Sanitize input passed to mail systems |
| 1.5.2 | 2 | Deserialize untrusted data safely, with allowed types |

## V2 Validation and Business Logic

| ID | L | Requirement |
|---|---|---|
| 2.1.1 | 1 | Document validation rules for data formats |
| 2.2.1 | 1 | Validate input positively against business expectations |
| 2.2.2 | 1 | Validate in a trusted service layer, not only on the client |
| 2.3.1 | 1 | Business flows run in order without skipped steps |
| 2.1.2 | 2 | Document consistency rules for related fields |
| 2.1.3 | 2 | Document business limits per user and globally |
| 2.2.3 | 2 | Check that related values make sense together |
| 2.3.2 | 2 | Implement the documented limits |
| 2.3.3 | 2 | Business operations are atomic and roll back on failure |
| 2.3.4 | 2 | Lock limited resources against double allocation |
| 2.4.1 | 2 | Defend against excessive automated calls |

## V3 Web Frontend Security

| ID | L | Requirement |
|---|---|---|
| 3.2.1 | 1 | Browsers cannot render responses in an unintended context |
| 3.2.2 | 1 | Insert text with safe functions such as `textContent` |
| 3.3.1 | 1 | Cookies are `Secure`, with a `__Host-` or `__Secure-` name prefix |
| 3.4.1 | 1 | HSTS on all responses, at least one year |
| 3.4.2 | 1 | CORS allowed origin is fixed or checked against an allowlist |
| 3.5.1 | 1 | Verify origin of sensitive cross-origin requests that skip preflight |
| 3.5.2 | 1 | If relying on preflight, no request can reach sensitive functions without it |
| 3.5.3 | 1 | Sensitive functions use unsafe methods or strict `Sec-Fetch-*` checks |
| 3.3.2 | 2 | `SameSite` set according to each cookie's purpose |
| 3.3.3 | 2 | `__Host-` prefix unless the cookie must be shared |
| 3.3.4 | 2 | Cookies not needed by scripts are `HttpOnly` and set by header only |
| 3.4.3 | 2 | CSP with `object-src 'none'`, `base-uri 'none'` and allowlist, nonces or hashes |
| 3.4.4 | 2 | `X-Content-Type-Options: nosniff` everywhere |
| 3.4.5 | 2 | Referrer policy prevents leaking sensitive data |
| 3.4.6 | 2 | `frame-ancestors` on every response |
| 3.5.4 | 2 | Separate applications use separate hostnames |
| 3.5.5 | 2 | Discard `postMessage` data from untrusted origins or with bad syntax |
| 3.7.1 | 2 | No obsolete client technologies |
| 3.7.2 | 2 | Automatic redirects only to allowed destinations |

## V4 API and Web Service

| ID | L | Requirement |
|---|---|---|
| 4.1.1 | 1 | Correct `Content-Type` with charset on responses with a body |
| 4.4.1 | 1 | WebSockets use WSS |
| 4.1.2 | 2 | Only user-facing endpoints redirect HTTP to HTTPS |
| 4.1.3 | 2 | Users cannot override headers set by intermediaries |
| 4.2.1 | 2 | Message boundaries parsed consistently (request smuggling) |
| 4.3.1 | 2 | GraphQL queries limited by depth, cost or allowlist |
| 4.3.2 | 2 | GraphQL introspection off in production unless intended |
| 4.4.2 | 2 | WebSocket handshake checks `Origin` |
| 4.4.3 | 2 | Dedicated WebSocket tokens when the normal session cannot be used |
| 4.4.4 | 2 | WebSocket tokens issued over the authenticated HTTPS session |

## V5 File Handling

| ID | L | Requirement |
|---|---|---|
| 5.2.1 | 1 | Accept only sizes that cannot cause denial of service |
| 5.2.2 | 1 | File content matches its extension |
| 5.3.1 | 1 | Uploaded files in public folders never execute on the server |
| 5.3.2 | 1 | Build paths from trusted data or strictly validated names |
| 5.1.1 | 2 | Document allowed types and sizes, including unpacked size |
| 5.2.3 | 2 | Check archive size and file count before extracting |
| 5.4.1 | 2 | Validate or ignore submitted filenames; set the download name |
| 5.4.2 | 2 | Encode filenames in response headers |
| 5.4.3 | 2 | Scan files from untrusted sources for malware |

## V6 Authentication

| ID | L | Requirement |
|---|---|---|
| 6.1.1 | 1 | Document rate limiting and anti-automation without enabling lockout abuse |
| 6.2.1 | 1 | Passwords of at least 8 characters, 15 recommended |
| 6.2.2 | 1 | Users can change passwords |
| 6.2.3 | 1 | Change requires the current password |
| 6.2.4 | 1 | Check against at least the 3000 most common passwords |
| 6.2.5 | 1 | No composition rules |
| 6.2.6 | 1 | Mask password fields |
| 6.2.7 | 1 | Allow paste and password managers |
| 6.2.8 | 1 | Verify the password exactly as entered |
| 6.3.1 | 1 | Control credential stuffing and brute force |
| 6.3.2 | 1 | No default accounts |
| 6.4.1 | 1 | Initial secrets are random, short-lived and temporary |
| 6.4.2 | 1 | No hints or secret questions |
| 6.2.10 | 2 | No scheduled expiry |
| 6.2.12 | 2 | Check against breached passwords |
| 6.3.3 | 2 | Require MFA or a combination of factors |
| 6.3.4 | 2 | No undocumented login paths; equal controls on all |
| 6.4.3 | 2 | Password reset cannot bypass MFA |
| 6.5.1 | 2 | One-time codes work once |
| 6.5.5 | 2 | Out-of-band codes last at most 10 minutes, TOTP 30 seconds |
| 6.6.2 | 2 | Out-of-band codes are bound to their request |
| 6.6.3 | 2 | Rate-limit code-based verification |
| 6.8.1 | 2 | With several identity providers, identify users by provider and user ID |
| 6.8.2 | 2 | Always verify assertion signatures |
| 6.8.4 | 2 | Check authentication strength claims for sensitive functions |

## V7 Session Management

| ID | L | Requirement |
|---|---|---|
| 7.2.1 | 1 | Verify session tokens in a trusted backend |
| 7.2.2 | 1 | Use dynamic tokens, not static API secrets |
| 7.2.3 | 1 | Reference tokens from a CSPRNG with 128 bits or more |
| 7.2.4 | 1 | New token on authentication; end the old one |
| 7.4.1 | 1 | Logout or expiry makes the session unusable |
| 7.4.2 | 1 | Disabling or deleting an account ends its sessions |
| 7.1.1 | 2 | Document inactivity and absolute timeouts |
| 7.1.2 | 2 | Document concurrent session limits |
| 7.1.3 | 2 | Document how federated session lifetimes interact |
| 7.3.1 | 2 | Inactivity timeout |
| 7.3.2 | 2 | Absolute lifetime |
| 7.4.3 | 2 | Offer to end other sessions after factor changes |
| 7.4.4 | 2 | Logout visible on authenticated pages |
| 7.4.5 | 2 | Administrators can end sessions |
| 7.5.1 | 2 | Re-authenticate before changing recovery or MFA data |
| 7.5.2 | 2 | Users can view and end their sessions |
| 7.6.1 | 2 | Provider and application session lifetimes behave as documented |
| 7.6.2 | 2 | New sessions require user action or consent |

## V8 Authorization

| ID | L | Requirement |
|---|---|---|
| 8.1.1 | 1 | Document function and data access rules |
| 8.2.1 | 1 | Functions require explicit permission |
| 8.2.2 | 1 | Each data object requires explicit permission (IDOR, BOLA) |
| 8.3.1 | 1 | Enforce in a trusted service layer |
| 8.1.2 | 2 | Document field-level rules |
| 8.2.3 | 2 | Enforce field-level access |
| 8.4.1 | 2 | Isolate tenants |

## V9 Self-contained Tokens

| ID | L | Requirement |
|---|---|---|
| 9.1.1 | 1 | Verify signature or MAC before trusting content |
| 9.1.2 | 1 | Allowlist algorithms; no `none`; prevent key confusion |
| 9.1.3 | 1 | Keys only from trusted sources; control `jku`, `x5u`, `jwk` |
| 9.2.1 | 1 | Enforce the validity period |
| 9.2.2 | 2 | Check the token type fits the use |
| 9.2.3 | 2 | Check audience |
| 9.2.4 | 2 | Shared signing keys require a distinct audience per target |

## V10 OAuth and OIDC

| ID | L | Requirement |
|---|---|---|
| 10.4.1 | 1 | Exact match of registered redirect URIs |
| 10.4.2 | 1 | Authorization codes work once; reuse revokes tokens |
| 10.4.3 | 1 | Codes expire quickly (10 minutes at most for L1 and L2) |
| 10.4.4 | 1 | Only needed grants; no implicit or password grant |
| 10.4.5 | 1 | Protect public-client refresh tokens against replay |
| 10.1.2 | 2 | Accept responses only for flows the session started; bind state, nonce and verifier |
| 10.2.1 | 2 | Protect the code flow with PKCE or state |
| 10.2.2 | 2 | Defend against authorization server mix-up |
| 10.3.1 | 2 | Resource servers check audience |
| 10.3.2 | 2 | Resource servers enforce scope and claims |
| 10.3.3 | 2 | Identify users by issuer and subject |
| 10.4.6 | 2 | Require PKCE without the `plain` method |
| 10.4.8 | 2 | Refresh tokens have an absolute expiry |
| 10.4.10 | 2 | Confidential clients authenticate on back-channel calls |
| 10.5.1 | 2 | Check the ID token nonce |
| 10.5.2 | 2 | Identify users by `sub` within a provider |
| 10.5.4 | 2 | ID token audience equals the client ID |

## V11 Cryptography

| ID | L | Requirement |
|---|---|---|
| 11.3.1 | 1 | No insecure modes or weak padding |
| 11.3.2 | 1 | Only approved ciphers and modes |
| 11.4.1 | 1 | Only approved hash functions; no MD5 for cryptography |
| 11.1.1 | 2 | Documented key management policy |
| 11.1.2 | 2 | Cryptographic inventory |
| 11.2.1 | 2 | Use validated implementations |
| 11.2.2 | 2 | Algorithms and keys can be replaced |
| 11.2.3 | 2 | At least 128 bits of security |
| 11.3.3 | 2 | Protect ciphertext integrity |
| 11.4.2 | 2 | Store passwords with a slow approved function |
| 11.4.3 | 2 | Hashes for signatures and integrity are long enough |
| 11.4.4 | 2 | Derive keys from passwords with an approved KDF |
| 11.5.1 | 2 | Unguessable values from a CSPRNG, 128 bits; UUIDs excluded |
| 11.6.1 | 2 | Approved key generation and signature algorithms |

## V12 Secure Communication

| ID | L | Requirement |
|---|---|---|
| 12.1.1 | 1 | Only current TLS versions |
| 12.2.1 | 1 | TLS for external client traffic without fallback |
| 12.2.2 | 1 | Publicly trusted certificates externally |
| 12.1.2 | 2 | Recommended cipher suites only |
| 12.1.3 | 2 | Validate client certificates before trusting identity |
| 12.3.1 | 2 | Encrypt all inbound and outbound connections |
| 12.3.2 | 2 | Clients validate server certificates |
| 12.3.3 | 2 | Encrypt internal HTTP services |
| 12.3.4 | 2 | Trust only specific internal authorities or pinned certificates |

## V13 Configuration

| ID | L | Requirement |
|---|---|---|
| 13.4.1 | 1 | No version control data deployed or reachable |
| 13.1.1 | 2 | Document all communication needs |
| 13.2.1 | 2 | Backend components use service identities or short-lived credentials |
| 13.2.2 | 2 | Backend components have least privilege |
| 13.2.3 | 2 | No default service credentials |
| 13.2.4 | 2 | Allowlist external resources |
| 13.2.5 | 2 | Restrict outbound connections from servers |
| 13.3.1 | 2 | Keep backend secrets in a secrets manager, never in source or artifacts |
| 13.4.2 | 2 | Debug off in production |
| 13.4.3 | 2 | No unintended directory listing |
| 13.4.4 | 2 | HTTP TRACE disabled |
| 13.4.5 | 2 | Documentation and monitoring endpoints not exposed unintentionally |

## V14 Data Protection

| ID | L | Requirement |
|---|---|---|
| 14.2.1 | 1 | No sensitive data in URLs |
| 14.3.1 | 1 | Clear client-side data when the session ends |
| 14.1.1 | 2 | Identify and classify sensitive data, including encoded data |
| 14.1.2 | 2 | Document protection per classification |
| 14.2.2 | 2 | Do not cache sensitive data in server components, or purge it |
| 14.2.3 | 2 | No sensitive data to untrusted third parties |
| 14.2.4 | 2 | Implement the documented protections |
| 14.3.2 | 2 | Anti-caching headers on sensitive responses |
| 14.3.3 | 2 | Browser storage holds no sensitive data except session tokens |

## V15 Secure Coding and Architecture

| ID | L | Requirement |
|---|---|---|
| 15.1.1 | 1 | Document deadlines for fixing vulnerable components |
| 15.2.1 | 1 | No components past those deadlines |
| 15.3.1 | 1 | Return only the fields needed |
| 15.1.2 | 2 | Maintain an inventory or SBOM from trusted sources |
| 15.1.3 | 2 | Document resource-heavy functions and defenses |
| 15.2.2 | 2 | Implement those defenses |
| 15.2.3 | 2 | No test or sample code in production |
| 15.3.2 | 2 | Do not follow outbound redirects unless intended |
| 15.3.3 | 2 | Prevent mass assignment |
| 15.3.4 | 2 | Take the client IP only from trusted fields |
| 15.3.5 | 2 | Strict types and strict comparisons |
| 15.3.6 | 2 | Prevent prototype pollution |
| 15.3.7 | 2 | Prevent HTTP parameter pollution |

## V16 Security Logging and Error Handling

No Level 1 requirements: logging starts at L2.

| ID | L | Requirement |
|---|---|---|
| 16.1.1 | 2 | Inventory of logging: format, storage, access, retention |
| 16.2.1 | 2 | Entries record who, what, when and where |
| 16.2.5 | 2 | Protect sensitive data in logs; hash or mask tokens |
| 16.3.1 | 2 | Log successful and failed authentication |
| 16.3.2 | 2 | Log failed authorization |
| 16.3.3 | 2 | Log documented security events and bypass attempts |
| 16.3.4 | 2 | Log unexpected errors and control failures |
| 16.4.1 | 2 | Encode entries against log injection |
| 16.4.2 | 2 | Protect logs from access and change |
| 16.4.3 | 2 | Ship logs to a separate system |
| 16.5.1 | 2 | Generic error messages to users |
| 16.5.2 | 2 | Stay safe when external resources fail |
| 16.5.3 | 2 | Fail securely, never open |

## V17 WebRTC

No Level 1 requirements.

| ID | L | Requirement |
|---|---|---|
| 17.1.1 | 2 | TURN relays only to public addresses |
| 17.2.1 | 2 | Manage the DTLS key under the key policy |
| 17.2.2 | 2 | Approved DTLS suites and SRTP profile |
| 17.2.3 | 2 | Verify SRTP authentication |
| 17.2.4 | 2 | Media server survives malformed packets |
| 17.3.1 | 2 | Signaling server withstands floods |
| 17.3.2 | 2 | Signaling server survives malformed messages |
