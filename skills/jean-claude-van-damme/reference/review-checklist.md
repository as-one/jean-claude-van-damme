# Review Checklist

Coverage aid for step 4 of the workflow in `SKILL.md`. Open only the sections the target touches. An unmet item is a lead, not a finding: trace it and apply the triage rubric before reporting. Items that only add defense in depth are hardening notes.

Section titles give the OWASP Top 10:2025 category and, where useful, the ASVS 5.0 chapter.

## Contents

- [Before you start](#before-you-start)
- [Changes in a diff](#changes-in-a-diff)
- [Access control](#access-control)
- [Authentication](#authentication)
- [Sessions and tokens](#sessions-and-tokens)
- [OAuth, OIDC and SSO](#oauth-oidc-and-sso)
- [Input and injection](#input-and-injection)
- [Web frontend](#web-frontend)
- [APIs, GraphQL and real-time](#apis-graphql-and-real-time)
- [Server-side requests and webhooks](#server-side-requests-and-webhooks)
- [Files and archives](#files-and-archives)
- [Business logic and concurrency](#business-logic-and-concurrency)
- [Cryptography and secrets](#cryptography-and-secrets)
- [Data protection and privacy](#data-protection-and-privacy)
- [Deserialization and integrity](#deserialization-and-integrity)
- [Errors, logging and alerting](#errors-logging-and-alerting)
- [Availability and resource limits](#availability-and-resource-limits)
- [Configuration](#configuration)
- [Containers, orchestration and cloud](#containers-orchestration-and-cloud)
- [Dependencies and supply chain](#dependencies-and-supply-chain)
- [CI/CD](#cicd)
- [Mobile and desktop](#mobile-and-desktop)
- [Native code](#native-code)
- [LLM features](#llm-features)
- [Agents, tools and MCP](#agents-tools-and-mcp)
- [Before closing the review](#before-closing-the-review)

## Before you start

- [ ] Entry points listed: routes, jobs, queues, webhooks, CLI arguments, uploads, model and tool inputs
- [ ] Actors and trust levels identified: anonymous, user, tenant admin, operator, service, outside contributor
- [ ] Valuable assets named: credentials, personal data, money or balances, signing keys, production access
- [ ] Central controls located: middleware, base classes, decorators, gateway, database policies
- [ ] Deployment context noted where visible: exposed ports, proxies, environments

## Changes in a diff

- [ ] No check removed, reordered after the sensitive operation, or made optional
- [ ] No validator, allowlist, CORS rule, permission or token scope widened
- [ ] New routes and handlers carry the same protection as their neighbors
- [ ] New dependencies, install scripts, workflows and build steps reviewed
- [ ] Feature flags and environment conditions cannot disable a control in production
- [ ] Callers of changed functions still satisfy the new assumptions
- [ ] History checked for why a removed security line existed

## Access control

A01, ASVS V8.

- [ ] Every route, resolver, action and job enforces authorization on the server
- [ ] Access is denied unless a rule grants it
- [ ] Each object lookup is limited to the caller's ownership or tenant, including nested and bulk operations
- [ ] Function-level checks separate user, admin and service operations
- [ ] Writable fields are listed explicitly, so role, owner, price and status cannot be mass assigned
- [ ] Read responses expose only fields the caller may see
- [ ] Tenant identity comes from the session or token, not from a request parameter
- [ ] Alternate paths are covered: other verbs, API versions, export, search, preview, direct file URLs
- [ ] Permission changes and revocations take effect in caches, sessions and issued links
- [ ] Redirect targets are relative or allowlisted

## Authentication

A07, ASVS V6.

- [ ] Passwords stored with Argon2id, scrypt or bcrypt and current work factors
- [ ] Login, reset, one-time code and signup flows resist guessing and credential stuffing
- [ ] Responses and timing do not reveal whether an account exists
- [ ] Reset and invitation tokens are random, single use, short lived and bound to the account
- [ ] Reset links are not built from an untrusted `Host` header
- [ ] Changing email, password or second factor requires recent authentication and notifies the user
- [ ] MFA cannot be skipped through another endpoint, legacy protocol or recovery flow
- [ ] No default accounts, hardcoded credentials or test bypasses in production paths

## Sessions and tokens

A07, ASVS V7 and V9.

- [ ] Session identifiers come from a CSPRNG and are replaced at login and privilege change
- [ ] Cookies set `Secure`, `HttpOnly` and a suitable `SameSite`
- [ ] Logout, password change and account disable end existing sessions
- [ ] Idle and absolute lifetimes are enforced on the server
- [ ] Token signatures are verified with a pinned algorithm and a trusted key source
- [ ] Issuer, audience, expiry and intended token type are checked
- [ ] Key identifiers and key URLs inside a token cannot select an attacker's key
- [ ] Tokens are absent from URLs, logs and storage readable by scripts where avoidable

## OAuth, OIDC and SSO

A07, ASVS V10.

- [ ] Redirect URIs match exactly
- [ ] Authorization code flow with PKCE; implicit and password grants not used
- [ ] `state` or an equivalent protects against CSRF; `nonce` is checked for ID tokens
- [ ] Users are identified by issuer and subject, not by email alone
- [ ] Account linking requires proof of control of both accounts
- [ ] SAML or other assertions: signature covers the data actually used, with audience and replay checks
- [ ] Scopes are minimal; refresh tokens are rotated or sender constrained

## Input and injection

A05, ASVS V1 and V2.

- [ ] Input validated on the server for type, length, range and format, preferring allowlists
- [ ] SQL, NoSQL, LDAP and search queries bind values; identifiers and sort keys are allowlisted
- [ ] Operating system commands use argument arrays, and user values cannot act as options
- [ ] No evaluation of input as code or expressions
- [ ] Templates are fixed; input is passed as data
- [ ] XML parsers refuse DTDs and external entities
- [ ] Headers, email fields and log lines reject or encode line breaks
- [ ] CSV and spreadsheet exports neutralize formula prefixes
- [ ] Regular expressions on untrusted text cannot backtrack catastrophically
- [ ] Data is validated again when it moves from storage into a dangerous sink

## Web frontend

A01 and A05, ASVS V3.

- [ ] Output encoded for its context: element, attribute, URL, script and style
- [ ] Raw HTML sinks receive only sanitized content
- [ ] URLs from users are limited to expected schemes
- [ ] State-changing requests that rely on cookies have CSRF protection, and `GET` changes nothing
- [ ] CORS lists trusted origins; no reflected or `null` origin with credentials
- [ ] `postMessage` verifies the sender origin and names the target origin
- [ ] Content Security Policy and framing restrictions are in place
- [ ] Third-party scripts are self-hosted or use Subresource Integrity
- [ ] No secrets or authorization decisions in client bundles; source maps considered
- [ ] Server-rendered state is serialized safely into the page

## APIs, GraphQL and real-time

A01 and A06, ASVS V4 and V17.

- [ ] Content types and methods are restricted to those expected
- [ ] Schema validation rejects unknown fields where that matters
- [ ] Pagination, batch size and filter complexity are bounded
- [ ] GraphQL: field-level authorization, depth and cost limits, aliases and batching counted in rate limits
- [ ] WebSocket handshake checks origin and authentication; each message is authorized
- [ ] Internal or debug endpoints are not exposed through the public gateway
- [ ] Proxy and application agree on request parsing and path normalization
- [ ] Shared caches cannot store or serve per-user responses to others
- [ ] WebRTC: TURN credentials are short lived and relays cannot reach internal addresses

## Server-side requests and webhooks

A01, ASVS V4 and V13.

- [ ] Destinations are allowlisted where the feature allows it
- [ ] Private, loopback and link-local addresses are blocked on the address actually connected to
- [ ] Redirects are disabled or checked at every hop
- [ ] URL fetchers inside libraries are covered: PDF, image, XML, link preview and import features
- [ ] Responses are size and time limited and not echoed raw
- [ ] Incoming webhooks verify a signature over the raw body, with a timestamp or event ID against replay
- [ ] Webhook handlers are idempotent

## Files and archives

A01, ASVS V5.

- [ ] Paths built from input are resolved and confined to a base directory, symlinks included
- [ ] Upload type checked by content; names generated by the server
- [ ] Uploads cannot be executed or rendered as active content on the application origin
- [ ] Size, count and per-user quota limits exist
- [ ] Archive extraction rejects traversal and links, and limits expanded size and entries
- [ ] Image, document and media parsers are patched and isolated for untrusted input
- [ ] Download links are authorized or unguessable and expire
- [ ] Temporary files are created safely and removed

## Business logic and concurrency

A06, ASVS V2.

- [ ] Prices, totals, discounts, roles and state transitions are decided on the server
- [ ] Negative, zero, huge and fractional quantities are handled
- [ ] Workflow steps cannot be skipped, reordered or replayed
- [ ] Balances, stock, coupons and quotas change atomically
- [ ] Retried payments and requests use idempotency keys
- [ ] Check and use happen under the same transaction or lock
- [ ] Abuse at scale considered: automation, enumeration, referral or trial farming
- [ ] High-value actions require step-up or a second approval

## Cryptography and secrets

A04, ASVS V11 and V12.

- [ ] Established libraries and constructions; nothing custom
- [ ] Authenticated encryption, with nonces never reused under a key
- [ ] Random values for security come from a CSPRNG
- [ ] Secret comparisons are constant time
- [ ] TLS used for every connection, with certificate and hostname verification
- [ ] No secrets in code, history, images, client bundles, logs or fixtures
- [ ] No fallback value when a secret is missing
- [ ] Keys have an owner, limited scope and a rotation path; exposed secrets are revoked, not only deleted

## Data protection and privacy

A04, ASVS V14.

- [ ] Sensitive data identified, minimized and given a retention period
- [ ] Encrypted at rest where the threat model calls for it
- [ ] Absent from URLs, analytics, error trackers and third-party requests
- [ ] Responses with sensitive data are not cached by browsers or proxies
- [ ] Deletion and export reach backups, indexes, caches and processors as promised
- [ ] Production data is not copied into development or test without masking

## Deserialization and integrity

A08, ASVS V15.

- [ ] No native deserialization of untrusted data
- [ ] Parsers do not instantiate types chosen by the input
- [ ] Recursive merges cannot alter prototypes or class attributes
- [ ] Updates, plugins, models and downloaded code are verified by signature or pinned hash
- [ ] Client-held data that the server trusts is signed and verified

## Errors, logging and alerting

A09 and A10, ASVS V16.

- [ ] Errors deny by default; a failing check never lets the request continue
- [ ] Partial failures roll back or leave a safe state
- [ ] No empty handlers around security operations
- [ ] Clients receive generic messages; details stay in server logs
- [ ] Authentication, authorization failures, administrative actions and sensitive changes are logged with actor and time
- [ ] Logs exclude passwords, tokens, keys and unneeded personal data
- [ ] Log entries cannot be forged through input, and logs are protected from alteration
- [ ] Someone is alerted on the events that matter

## Availability and resource limits

A06 and A10.

- [ ] Request, body, header, upload and decompression sizes are limited
- [ ] Outbound calls and database queries have timeouts
- [ ] Expensive operations have per-user limits and quotas
- [ ] Queues, pools, recursion and retries are bounded, with backoff
- [ ] A single request cannot crash the process
- [ ] Operations that cost money (email, SMS, model calls) are capped

## Configuration

A02, ASVS V13.

- [ ] Debug modes, consoles, profilers and sample applications are off in production
- [ ] Default credentials removed
- [ ] Unused services, ports, methods and features disabled
- [ ] Security headers set (see `iac-and-ci.md`)
- [ ] Repository metadata, environment files, backups and directory listings are not served
- [ ] Forwarding and identity headers are trusted only from known proxies
- [ ] Environments are isolated, with separate credentials
- [ ] DNS records do not point to unclaimed resources

## Containers, orchestration and cloud

A02, ASVS V13. Details in `iac-and-ci.md`.

- [ ] Containers run unprivileged, without host namespaces, host paths or the Docker socket
- [ ] No secrets in image layers or manifests
- [ ] Base images pinned
- [ ] RBAC and IAM grant specific actions on specific resources
- [ ] Network exposure limited; databases and admin interfaces are private
- [ ] Storage is private unless publication is intended
- [ ] Instance metadata access hardened
- [ ] Infrastructure state is protected; audit logging enabled

## Dependencies and supply chain

A03, ASVS V15.

- [ ] Lockfile committed and enforced in CI
- [ ] New packages exist, are the intended ones and are maintained
- [ ] Internal package names cannot be claimed publicly
- [ ] Install and build scripts reviewed
- [ ] Lockfile changes match manifest changes and point to expected registries
- [ ] Known vulnerabilities checked for reachability
- [ ] Vendored and copied code has a known origin
- [ ] Releases carry provenance or signatures that deployment verifies

## CI/CD

A03 and A08.

- [ ] Untrusted code never runs with secrets or write permissions
- [ ] Event data is not interpolated into scripts
- [ ] Third-party actions, images and includes are pinned
- [ ] Token permissions are minimal; cloud access uses short-lived credentials with a restricted trust policy
- [ ] Caches and artifacts do not cross trust levels unverified
- [ ] Production deployment requires review on protected branches or environments
- [ ] Self-hosted runners are isolated and disposable

## Mobile and desktop

ASVS V14 where applicable.

- [ ] Secrets and tokens use platform secure storage; no server secrets shipped in the app
- [ ] Certificate validation intact; cleartext traffic disabled
- [ ] Exported components, URL schemes and deep links validate caller and parameters
- [ ] WebViews and renderers cannot reach privileged bridges from remote content
- [ ] Desktop shells (Electron and similar): context isolation on, Node integration off for remote content, IPC arguments validated
- [ ] Auto-update verifies signatures
- [ ] Authorization is enforced by the server

## Native code

- [ ] Lengths and indices from input are validated before use
- [ ] Size arithmetic checked for overflow and signedness
- [ ] Ownership and lifetimes clear; no use after free or double free
- [ ] Format strings are literals
- [ ] `unsafe` and foreign function boundaries state and enforce their invariants
- [ ] Parsers of untrusted data are fuzzed and built with sanitizers in testing

## LLM features

LLM Top 10 2026. Details in `owasp-ai.md`.

- [ ] All text reaching the model is classed as trusted or untrusted, including documents, pages and tool results (LLM01)
- [ ] Data in context is limited to what this user may see (LLM02)
- [ ] The model can only do what the task needs (LLM03)
- [ ] Models, adapters, prompts and packages have trusted, pinned sources (LLM04)
- [ ] Training, tuning and indexed data cannot be poisoned by unreviewed input (LLM05)
- [ ] Requests, tokens, time and cost are capped per user (LLM06)
- [ ] Important outputs are grounded or reviewed before people or code rely on them (LLM07)
- [ ] System prompts and hidden context hold no secrets and enforce no access control (LLM08)
- [ ] Retrieval applies tenant and permission filters at query time (LLM09)
- [ ] Output is validated or encoded before reaching HTML, SQL, a shell, a URL or a tool (LLM10)

## Agents, tools and MCP

Agentic Top 10 2026. Details in `owasp-ai.md`.

- [ ] Untrusted content cannot redirect the goal of an agent holding sensitive tools (ASI01)
- [ ] Tools are narrow, validate arguments and require approval for irreversible actions (ASI02)
- [ ] Credentials are scoped to the task and user, and short lived (ASI03)
- [ ] MCP servers, plugins, skills and hooks are pinned and reviewed (ASI04)
- [ ] Generated code runs isolated, without ambient credentials or open network access (ASI05)
- [ ] Writes to memory and shared stores are validated and traceable (ASI06)
- [ ] Messages between agents are authenticated and not treated as authority (ASI07)
- [ ] Step, retry and fan-out limits stop one failure from spreading (ASI08)
- [ ] Approval prompts show the exact action and parameters (ASI09)
- [ ] Actions are logged, and an agent can be stopped and its access revoked (ASI10)

## Before closing the review

- [ ] Every finding names source, path, sink, impact and fix
- [ ] Each finding passed all rules of the triage rubric, or is labeled "needs verification"
- [ ] Duplicates merged under the root cause
- [ ] The same flaw searched for in sibling code
- [ ] Secrets masked in the report
- [ ] Files, directories and checks not covered are listed
