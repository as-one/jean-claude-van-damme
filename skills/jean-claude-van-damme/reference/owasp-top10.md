# OWASP Top 10:2025 in Detail

Read only the categories the target touches. Each entry lists what to look for, how it is attacked, how to prevent it, and what usually is not a finding. Apply the triage rubric in `SKILL.md` before reporting.

Source: https://top10.owasp.org/2025 (checked 2026-11-26). These are summaries in this project's words, with added review guidance and examples. Original material: OWASP Top 10 Team, CC BY 3.0.

## Contents

- [A01 Broken Access Control](#a01-broken-access-control)
- [A02 Security Misconfiguration](#a02-security-misconfiguration)
- [A03 Software Supply Chain Failures](#a03-software-supply-chain-failures)
- [A04 Cryptographic Failures](#a04-cryptographic-failures)
- [A05 Injection](#a05-injection)
- [A06 Insecure Design](#a06-insecure-design)
- [A07 Authentication Failures](#a07-authentication-failures)
- [A08 Software or Data Integrity Failures](#a08-software-or-data-integrity-failures)
- [A09 Security Logging and Alerting Failures](#a09-security-logging-and-alerting-failures)
- [A10 Mishandling of Exceptional Conditions](#a10-mishandling-of-exceptional-conditions)

## A01 Broken Access Control

Users act outside their permissions: reading, changing or deleting data, or running actions beyond their limits. Includes SSRF. ASVS: V8, V3, V5.

**Look for**
- Routes with no authorization, or checks only on `GET` while `POST`, `PUT` and `DELETE` are open.
- Object IDs from the request used without an ownership or tenant filter.
- Access rules enforced only in the UI.
- Roles, tenant IDs or prices accepted from the client; tampered cookies, JWTs or hidden fields.
- Permissive CORS; state-changing requests without CSRF protection; open redirects.
- Paths and URLs built from user input; directory listing, `.git` or backups under the web root.

**Attack vectors:** changing an account number in a URL; browsing directly to an admin route; calling with a script an endpoint the UI hides.

**Prevent**
- Deny by default for everything not public.
- Enforce in one trusted server-side layer and reuse it.
- Scope queries by owner or tenant.
- Invalidate sessions server-side on logout; keep JWTs short-lived and revoke long-lived refresh tokens.
- Log failures, alert on repeats, rate-limit APIs, and test access rules automatically.

```ts
// Vulnerable: authenticated, not authorized
app.delete("/api/projects/:id", requireLogin, async (req, res) => {
  await db.project.delete({ where: { id: req.params.id } });
  res.sendStatus(204);
});

// Fixed
const { count } = await db.project.deleteMany({
  where: { id: req.params.id, ownerId: req.user.id },
});
res.sendStatus(count ? 204 : 404);
```

**Not a finding:** a route protected by middleware or a base class that you can see; public data served without login by design.

## A02 Security Misconfiguration

A system, framework or cloud service is set up insecurely. ASVS: V13, V3, V12. See also `iac-and-ci.md`.

**Look for**
- Debug mode, stack traces, version banners.
- Default accounts and passwords, sample apps, unused ports, features and admin consoles.
- Missing security headers and unsafe framework or database defaults.
- Public storage buckets and open security groups.
- XML parsers with external entities enabled.
- Static long-lived secrets in configuration.

**Attack vectors:** logging in to a forgotten console with default credentials; listing a directory to download code; using an error page to identify vulnerable versions.

**Prevent**
- Automated, repeatable hardening; the same configuration in every environment with different credentials.
- Minimal platform; configuration review as part of patching; segmentation.
- Central error handling; short-lived or role-based credentials.
- Verify configuration automatically, or at least review it yearly.

```yaml
# Vulnerable: management endpoints and error detail exposed
management.endpoints.web.exposure.include: "*"
server.error.include-stacktrace: always

# Fixed
management.endpoints.web.exposure.include: health
server.error.include-stacktrace: never
```

**Not a finding:** a development setting in a file that is only loaded locally.

## A03 Software Supply Chain Failures

Compromise through the way software is built, distributed or updated: dependencies (direct and transitive), tools, registries and pipelines. ASVS: V15. See `iac-and-ci.md`.

**Look for**
- Unknown component inventory, unsupported or unpatched libraries, no vulnerability monitoring.
- Missing or unenforced lockfiles; packages from untrusted sources; invented or look-alike names.
- Install scripts; CI actions or images referenced by mutable tags.
- A pipeline with weaker protection than the system it deploys; one person able to write and ship alone.

**Attack vectors:** a trusted vendor ships a malicious update; a worm spreads through packages and steals developer tokens; payload that activates only under chosen conditions; a known library flaw left unpatched.

**Prevent**
- SBOM covering transitive dependencies; monitoring against CVE, NVD and OSV.
- Pinned versions from official sources, signed where possible.
- Hardened repositories, build servers and registries with MFA and least privilege; signed builds and provenance.
- Staged or canary rollout of updates.

```yaml
# Vulnerable: the tag can be moved to other code
- uses: some-org/deploy-action@v3

# Fixed: full commit SHA, with the version noted
- uses: some-org/deploy-action@<40-character-commit-sha> # v3.2.1
```

**Not a finding:** an outdated package whose vulnerable function is unreachable (note it as maintenance).

## A04 Cryptographic Failures

Missing, weak or misused cryptography, and leaked keys. ASVS: V11, V12, V14.

**Look for**
- Plaintext protocols; old TLS; missing HSTS; certificate validation disabled.
- MD5, SHA-1 or a fast hash for passwords; no salt.
- ECB, unauthenticated CBC, PKCS#1 v1.5; reused IV or nonce.
- Passwords used directly as keys; hardcoded or default keys.
- `Math.random`, `rand` or similar for tokens.

**Attack vectors:** downgrading to HTTP on a hostile network and stealing a session cookie; cracking a dumped table of fast hashes offline.

**Prevent**
- Classify data and keep as little as possible; disable caching of sensitive responses.
- TLS 1.2 or higher with forward secrecy, plus HSTS.
- Passwords: Argon2id, scrypt, yescrypt or PBKDF2-HMAC-SHA-512; bcrypt only for existing systems.
- Authenticated encryption, unique nonces, CSPRNG keys, KDF for password-derived keys.
- Most sensitive keys in an HSM or KMS; plan the move to post-quantum algorithms for high-risk systems.

```python
# Vulnerable
digest = hashlib.sha256(password.encode()).hexdigest()

# Fixed
from argon2 import PasswordHasher
digest = PasswordHasher().hash(password)
```

**Not a finding:** MD5 or SHA-1 used as a cache key or checksum with no security decision depending on it.

## A05 Injection

Untrusted input is interpreted as part of a command or query: SQL, NoSQL, OS, ORM, LDAP, expression languages, XSS. LLM prompt injection is covered in `owasp-ai.md`. ASVS: V1, V2.

**Look for**
- Concatenation or interpolation into queries, commands, templates or markup.
- ORM raw fragments and search parameters taken as is.
- User-controlled table names, column names or sort order.
- Stored procedures that build dynamic SQL.

**Attack vectors:** a quote that turns a filter into "match everything"; chaining a second command after a hostname passed to a shell.

**Prevent**
- Safe APIs that separate data from commands: bound parameters, argument arrays, auto-escaping templates.
- Allowlist identifiers, which cannot be parameterized.
- Server-side positive validation; contextual escaping only where no safe API exists.
- SAST, DAST and fuzzing in CI.

```java
// Vulnerable
String sql = "SELECT * FROM users ORDER BY " + request.getParameter("sort");

// Fixed
Map<String, String> columns = Map.of("name", "name", "date", "created_at");
String column = columns.getOrDefault(request.getParameter("sort"), "created_at");
String sql = "SELECT * FROM users ORDER BY " + column;
```

**Not a finding:** interpolation of constants or allowlisted values.

## A06 Insecure Design

A needed control is missing or cannot work, even with flawless code. ASVS: V2, V15.

**Look for**
- Business rules enforced only on the client; steps that can be skipped or replayed.
- No limits on quantities, frequency or cost.
- Credentials stored without protection; trusted and untrusted data mixed in one object or session.
- Unrestricted upload; no tenant separation; recovery based on security questions.

**Attack vectors:** booking far beyond a group limit; bots buying all stock; abusing a weak recovery flow.

**Prevent**
- Threat model authentication, access control, business logic and key flows.
- Reuse reviewed design patterns and components.
- Check plausibility at each tier; test misuse cases as well as use cases.
- Separate tiers and tenants.

```python
# Vulnerable: check then act, two requests can redeem the same coupon
if not coupon.used:
    apply(coupon)
    coupon.used = True

# Fixed: one conditional update decides
claimed = Coupon.objects.filter(id=coupon.id, used=False).update(used=True)
if claimed:
    apply(coupon)
```

**Not a finding:** a missing control with no plausible abuse for this system; say it is a design suggestion.

## A07 Authentication Failures

The system accepts a wrong or forged identity. ASVS: V6, V7, V9, V10.

**Look for**
- No protection against credential stuffing, spraying or brute force.
- Default, weak or breached passwords allowed; weak recovery; weak hashing.
- Missing MFA; session ID in URLs; no new ID after login; logout that leaves the session valid.
- JWT without `aud`, `iss`, expiry or scope checks.

**Attack vectors:** trying leaked passwords with small variations; reusing a session left open on a shared computer; using a still-valid SSO session after logging out of one application.

**Prevent**
- MFA; allow password managers; no default credentials.
- Reject common and breached passwords; follow NIST 800-63B; no scheduled rotation.
- Identical responses to avoid account enumeration; progressive delays with logging and alerts, without enabling lockout abuse.
- Server-side session manager with high-entropy IDs, secure cookies, idle and absolute timeouts.
- Prefer an established identity system.

```js
// Vulnerable: session fixation
req.session.userId = user.id;

// Fixed
req.session.regenerate((err) => {
  if (err) return next(err);
  req.session.userId = user.id;
  res.redirect("/home");
});
```

**Not a finding:** missing MFA on a low-value system when nothing requires it; record it as hardening.

## A08 Software or Data Integrity Failures

Code or data is trusted without verifying where it came from or whether it changed. ASVS: V1, V15, V3.

**Look for**
- Native deserialization of untrusted data.
- Updates, plugins or firmware installed without signature checks.
- Scripts from CDNs without Subresource Integrity.
- Pipeline artifacts passed between jobs without verification.
- Client-held state with no signature.
- Third-party subdomains that receive the parent domain's cookies.

**Attack vectors:** a crafted serialized object that runs code (Java payloads often start with `rO0` in base64); a swapped unsigned update; a hosted subdomain collecting session cookies.

**Prevent**
- Verify signatures; use trusted repositories or a vetted mirror.
- Review code and configuration changes; isolate the pipeline.
- Do not accept serialized data without integrity protection; prefer plain data formats with schemas.

```html
<!-- Fixed: the browser rejects a modified file -->
<script src="https://cdn.example.org/widget.js"
        integrity="sha384-<base64-digest>" crossorigin="anonymous"></script>
```

**Not a finding:** deserialization of data the application itself wrote to storage an attacker cannot modify.

## A09 Security Logging and Alerting Failures

Attacks go unnoticed because events are not recorded, protected or acted on. ASVS: V16.

**Look for**
- Authentication, access-control failures and high-value actions not logged.
- Logs that are local only, editable, unclear or never monitored.
- No alerting, or so much noise that alerts are ignored.
- Passwords, tokens or personal data in logs; unencoded input in log lines.

**Attack vectors:** long-running breach that nobody sees; forged log lines hiding activity.

**Prevent**
- Structured logs with user and request context, for successes and failures of security controls.
- Encode input; append-only or tamper-evident audit trails.
- Alerts with response playbooks; honeytokens give high-signal detection.
- A tested incident response plan.

```python
# Vulnerable: secret in the log and injectable text
log.info(f"login {username} {password}")

# Fixed
log.info("login_failed", extra={"user": username[:64], "ip": ip})
```

**Not a finding:** missing debug logging with no security value. Logging gaps are usually Low unless the system must audit the action.

## A10 Mishandling of Exceptional Conditions

The program does not prevent, detect or handle abnormal situations. ASVS: V16, V2.

**Look for**
- Errors that grant access or continue processing (fail-open).
- Empty `catch` blocks; ignored return values on security calls.
- Partial transactions without rollback.
- Resources not released on error paths; no limits or quotas.
- Detailed errors sent to users; inconsistent handling across components.

**Attack vectors:** repeated failing uploads that exhaust resources; database errors that guide injection; interrupting a transfer to leave it half done or run it twice.

**Prevent**
- Handle errors where they happen, with a global handler as backstop.
- Fail closed and roll back completely.
- Rate limits, quotas and timeouts.
- Summarize repeated errors; test error paths and load.

```go
// Vulnerable: an error is treated as permission
allowed, err := policy.Check(user, doc)
if err == nil && !allowed {
    return ErrForbidden
}

// Fixed
allowed, err := policy.Check(user, doc)
if err != nil || !allowed {
    return ErrForbidden
}
```

**Not a finding:** a handled error with a generic message and no state left inconsistent.
