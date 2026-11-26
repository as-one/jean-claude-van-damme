# Language Pitfalls

Read only the sections for the languages under review. A match here is a lead: trace it from source to sink and apply the triage rubric in `SKILL.md` before reporting. Each section ends with cases that look dangerous but usually are not.

## Contents

- [JavaScript and TypeScript](#javascript-and-typescript)
- [Python](#python)
- [Java and Kotlin](#java-and-kotlin)
- [C# and .NET](#c-and-net)
- [Go](#go)
- [PHP](#php)
- [Ruby](#ruby)
- [Rust](#rust)
- [C and C++](#c-and-c)
- [Shell](#shell)
- [Swift, Android and Flutter](#swift-android-and-flutter)
- [SQL](#sql)

## JavaScript and TypeScript

| Look for | Risk | Use instead |
|---|---|---|
| `eval`, `new Function`, `vm.runInNewContext` | Code execution (`vm` is not a sandbox) | A parser or a dispatch table |
| `child_process.exec` with interpolation, `shell: true` | Command injection | `execFile` or `spawn` with an argument array |
| `innerHTML`, `dangerouslySetInnerHTML`, `v-html` | XSS | Text nodes, framework escaping, DOMPurify |
| `href={userUrl}` | `javascript:` URLs | Allowlist `http:` and `https:` |
| Recursive merge or path set on parsed input | Prototype pollution | Schema validation, `Map`, block `__proto__`, `constructor`, `prototype` |
| `find({ user: req.body.user })` | NoSQL operator injection | Enforce types with a schema |
| `jwt.decode` | No signature check | `jwt.verify` with pinned `algorithms`, `audience`, `issuer` |
| `path.join(base, input)` | Path traversal | `path.resolve`, then require the `base + path.sep` prefix |
| `fetch(userUrl)` | SSRF | Host allowlist, block private ranges, re-check redirects |
| `res.redirect(req.query.next)` | Open redirect | Relative paths or an allowlist |

```ts
// Vulnerable: a type annotation is not runtime validation
const { id } = req.body as { id: string };
await db.users.findOne({ _id: id }); // id may be { $ne: null }

// Fixed
const { id } = z.object({ id: z.string().uuid() }).parse(req.body);
```

Also check: `postMessage` handlers without an origin check, unhandled promise rejections on security checks, a missing `await` on an authorization call (the promise is truthy), and Next.js server actions or route handlers without their own authorization.

Usually safe: `{value}` in JSX text, `execFile` with a fixed binary and `--` before user arguments, tagged-template SQL helpers that bind parameters.

## Python

| Look for | Risk | Use instead |
|---|---|---|
| `pickle`, `marshal`, `shelve`, `torch.load` with `weights_only=False` | Code execution on load | JSON, safetensors, `weights_only=True` |
| `yaml.load` with `Loader` or `UnsafeLoader` | Code execution | `yaml.safe_load` |
| `subprocess` with `shell=True`, `os.system` | Command injection | Argument list |
| f-string or `%` inside `execute` | SQL injection | Bound parameters |
| `render_template_string(user)`, `Template(user)` | Template injection | Pass data as template variables |
| `user_template.format(obj)` | Attribute traversal leaks data | Literal template only |
| `os.path.join(base, user)` | An absolute `user` replaces `base` | `Path.resolve` and `is_relative_to` |
| `tarfile.extractall` | Files written outside the target | `filter="data"` |
| `requests` with `verify=False` | No certificate check | Default verification |
| `random` for tokens | Predictable values | `secrets` |
| `assert` for authorization | Removed under `python -O` | Explicit check that raises |

```python
# Vulnerable: authenticated, but any user can read any order
Order.objects.get(pk=order_id)

# Fixed: ownership is part of the query
Order.objects.get(pk=order_id, owner=request.user)
```

Also check: mutable default arguments holding per-user state, bare `except` that allows the request to continue, Django `mark_safe` and `|safe`, `DEBUG=True`.

Usually safe: ORM filters with keyword arguments, `subprocess.run([...])` without a shell, f-string SQL whose interpolated part comes from a fixed mapping.

## Java and Kotlin

| Look for | Risk | Use instead |
|---|---|---|
| `ObjectInputStream.readObject`, `XMLDecoder` | Deserialization RCE | JSON with explicit target types, `ObjectInputFilter` |
| Jackson default typing, SnakeYAML `new Yaml()` before 2.0 | Gadget instantiation | Disable default typing, `SafeConstructor` |
| `DocumentBuilderFactory` and other XML factories with defaults | XXE | Disable DTDs and external entities |
| String concatenation in JDBC, JPQL or HQL | Injection | `PreparedStatement`, named parameters |
| SpEL, OGNL or EL built from input | Expression injection | Fixed expressions |
| `InitialContext.lookup(user)`, vulnerable Log4j | JNDI injection | Fixed names, patched versions |
| `new File(base, user)`, zip entry names | Traversal, zip slip | Compare canonical or normalized paths |
| `java.util.Random` | Predictable tokens | `SecureRandom` |
| Spring `permitAll`, CSRF disabled, broad matchers | Missing access control | Deny by default; disable CSRF only for non-cookie auth |
| `@RequestBody` bound to an entity | Mass assignment | Request DTOs |

Kotlin: `!!` and platform types from Java can fail inside security checks; `data class` `toString` may log secrets.

Usually safe: CSRF disabled on a stateless API that only accepts bearer tokens.

## C# and .NET

| Look for | Risk | Use instead |
|---|---|---|
| `BinaryFormatter`, `TypeNameHandling` other than `None` | Deserialization RCE | `System.Text.Json` with known types |
| `FromSqlRaw` or `SqlCommand` with concatenation | SQL injection | `FromSqlInterpolated`, parameters |
| `Html.Raw`, `MarkupString` | XSS | Default Razor encoding |
| `Path.Combine(base, user)` | A rooted `user` replaces `base` | `Path.GetFullPath` and prefix check |
| `Process.Start` with a composed argument string | Argument or command injection | `ArgumentList`, no shell |
| Controller or minimal API without `[Authorize]` | Missing access control | Fallback authorization policy |
| Binding directly to entities | Over-posting | Input models |
| Certificate callback that returns `true` | No TLS verification | Remove the callback |

Usually safe: EF Core LINQ queries and `FromSql` with interpolated parameters.

## Go

| Look for | Risk | Use instead |
|---|---|---|
| `fmt.Sprintf` into `Query` or `Exec` | SQL injection | Placeholders |
| `exec.Command("sh", "-c", input)` | Command injection | Direct binary with arguments |
| `text/template` for HTML, `template.HTML(input)` | XSS | `html/template` |
| `filepath.Join(base, input)` | `..` escapes `base` | `filepath.IsLocal`, `os.Root` (Go 1.24+) |
| `math/rand` for secrets | Predictable values | `crypto/rand` |
| `InsecureSkipVerify: true` | No TLS verification | Proper root CAs |
| Ignored or shadowed `err` on auth paths | Fail-open | Return on error |
| `http.Get(userURL)` | SSRF | Custom dialer that checks the resolved IP |
| Shared maps across goroutines | Race, crash | Mutex, `sync.Map`; run with `-race` |
| `http.ListenAndServe` without timeouts | Slow-request DoS | `http.Server` with timeouts |

Also check: integer conversions that truncate lengths or IDs, and missing `return` after `http.Error`.

Usually safe: out-of-range access that only panics inside a recovered HTTP handler (report as availability only if it matters).

## PHP

| Look for | Risk | Use instead |
|---|---|---|
| `==` or `in_array` without strict mode on secrets | Type juggling | `===`, `hash_equals`, `password_verify` |
| `unserialize` | Object injection | `json_decode` |
| `include`, `require` with input | File inclusion | Allowlist |
| `system`, `exec`, `shell_exec`, backticks | Command injection | Avoid; otherwise `escapeshellarg` per argument |
| `extract`, `parse_str` | Variable overwrite | Explicit keys |
| `move_uploaded_file` keeping the client name | Web shell upload | Random name, outside the web root |
| `DB::raw`, `whereRaw` with interpolation | SQL injection | Bindings |
| `{!! $value !!}` | XSS | `{{ $value }}` |
| `$guarded = []` with `$request->all()` | Mass assignment | `$fillable`, validated data |

## Ruby

| Look for | Risk | Use instead |
|---|---|---|
| `Marshal.load`, `YAML.unsafe_load`, `YAML.load` on Psych below 4 | Code execution | `YAML.safe_load`, JSON |
| `send`, `constantize` with input | Arbitrary method or class | Allowlist |
| `system("cmd #{x}")`, `Kernel#open` with input | Command injection | `system("cmd", x)`, `File.open` |
| `where("name = '#{x}'")`, `order(params[:s])` | SQL injection | Hash conditions, column allowlist |
| `html_safe`, `raw` | XSS | Default escaping |
| `permit!` | Mass assignment | Explicit `permit` |
| `^` and `$` in validation regexes | Multiline bypass | `\A` and `\z` |

## Rust

| Look for | Risk | Use instead |
|---|---|---|
| `unsafe` blocks and FFI | Memory safety depends on manual invariants | Verify lengths, lifetimes and aliasing |
| `unwrap`, indexing on untrusted input | Panic, denial of service | `?`, `get` |
| Arithmetic on sizes | Silent wrap in release builds | `checked_*` operations |
| `format!` into SQL | SQL injection | Bound parameters |
| `Command::new("sh").arg("-c")` | Command injection | Direct command with `arg` |
| `Path::join` with input | Absolute or `..` paths escape | Validate components |
| `danger_accept_invalid_certs` | No TLS verification | Remove |

Usually safe: memory-safety concerns in code with no `unsafe` and no FFI.

## C and C++

| Look for | Risk | Use instead |
|---|---|---|
| `strcpy`, `strcat`, `sprintf`, `gets` | Buffer overflow | Bounded functions, `std::string` |
| `strncpy` | Missing terminator | `snprintf` and check truncation |
| `printf(input)` | Format string | `printf("%s", input)` |
| `malloc(n * size)` | Integer overflow, small buffer | Check overflow, `calloc` |
| Signed length compared with unsigned | Bounds bypass | Consistent unsigned types and range checks |
| Pointer use after `free` or container resize | Use after free | RAII, smart pointers, refresh references |
| `system`, `popen` | Command injection | `execve` family |
| `access` followed by `open` | TOCTOU race | Open first, then check the descriptor |

Recommend AddressSanitizer, UndefinedBehaviorSanitizer and fuzzing for parsers of untrusted data.

## Shell

| Look for | Risk | Use instead |
|---|---|---|
| Unquoted `$var` | Word splitting, globbing | `"$var"` |
| `eval`, `bash -c "$x"` | Command injection | Arrays: `"${args[@]}"` |
| User value starting with `-` | Option injection | `--` before arguments |
| `[[ $x -eq 1 ]]` or `$(( x ))` on input | Code execution through arithmetic evaluation | Validate digits first |
| Fixed names in `/tmp` | Symlink attacks | `mktemp` |
| `set -x` near secrets | Secrets in logs | Disable tracing |
| `curl ... \| sh` | Unverified remote code | Pin and verify a checksum |

Also check for missing `set -euo pipefail` where a failed security step would be ignored.

## Swift, Android and Flutter

| Look for | Risk | Use instead |
|---|---|---|
| Tokens in `UserDefaults`, `SharedPreferences` | Readable local secrets | Keychain, Keystore, secure storage |
| API keys compiled into the app | Anyone can extract them | Keep them on a server |
| ATS exceptions, `usesCleartextTraffic="true"` | Plaintext traffic | TLS |
| Trust manager or delegate accepting any certificate | Interception | Default validation |
| Exported activities, services, providers | Other apps can call them | `exported="false"` or permissions |
| Deep link parameters used directly | Unauthorized actions | Validate and confirm |
| WebView with a JavaScript bridge loading remote content | Native code reachable from the web | Restrict origins, remove the bridge |
| `try!`, force unwrap on external data | Crash | `guard`, `do`/`catch` |

## SQL

- Parameters bind values only. Table names, column names and sort direction need an allowlist.
- Stored procedures that build dynamic SQL are injectable even when the caller binds parameters.
- Escape `%` and `_` in `LIKE` input when wildcards would widen access or cost.
- Check that application accounts have least privilege and that multi-tenant tables enforce isolation (row-level security or a mandatory tenant filter).
- Read-then-write on balances, stock or coupons needs a transaction with locking or a conditional update.
