# Language Pitfalls

Read only the sections for the languages under review. A match here is a lead: trace it from source to sink and apply the triage rubric in `SKILL.md` before reporting. Each section ends with cases that look dangerous but usually are not.

## Contents

- [Cross-language checks](#cross-language-checks)
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
- [Swift and Android](#swift-and-android)
- [Dart and Flutter](#dart-and-flutter)
- [Scala](#scala)
- [Elixir](#elixir)
- [Lua](#lua)
- [Perl](#perl)
- [PowerShell](#powershell)
- [R](#r)
- [SQL](#sql)

## Cross-language checks

### Server-side requests (SSRF and DNS rebinding)

Validating a hostname and then fetching by hostname resolves DNS twice. An attacker who controls the record can answer with a public address for the check and an internal one for the connection.

| Check | Detail |
|---|---|
| Scheme and port | Allow only what the feature needs, normally `https` |
| Destination | Prefer an allowlist of hosts. A blocklist of ranges is the weaker option |
| Resolved addresses | Reject loopback, private, link-local (including `169.254.169.254`), unspecified and their IPv6 and IPv4-mapped forms |
| Pinning | Connect to the address that was validated, or validate inside the socket connect hook. Keep TLS verification against the original hostname |
| Redirects | Disable them, or run every check again on each hop |
| Response | Cap size and time; do not return raw upstream bodies or errors to the caller |

An egress proxy or network policy that blocks internal ranges is a stronger control than application checks. Look for one before rating severity.

### File uploads

- Check content, not only extension or `Content-Type`, and generate the stored name on the server.
- Store outside the web root; serve with `Content-Disposition: attachment` or from a separate origin.
- Limit size, count and decompressed size; treat SVG and HTML as active content.

### Comparing secrets

Tokens, API keys and webhook signatures need a constant-time comparison: `crypto.timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`, `CryptographicOperations.FixedTimeEquals`, `subtle.ConstantTimeCompare`, `hash_equals`. Verify webhook signatures over the raw body and check the timestamp to limit replay.

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

## Swift and Android

| Look for | Risk | Use instead |
|---|---|---|
| Tokens in `UserDefaults`, `SharedPreferences` | Readable local secrets | Keychain, Keystore |
| API keys compiled into the app | Anyone can extract them | Keep them on a server |
| ATS exceptions, `usesCleartextTraffic="true"` | Plaintext traffic | TLS |
| Trust manager or delegate accepting any certificate | Interception | Default validation |
| Exported activities, services, providers | Other apps can call them | `exported="false"` or permissions |
| Deep link parameters used directly | Unauthorized actions | Validate and confirm |
| WebView with a JavaScript bridge loading remote content | Native code reachable from the web | Restrict origins, remove the bridge |
| `try!`, force unwrap on external data | Crash | `guard`, `do`/`catch` |

## Dart and Flutter

| Look for | Risk | Use instead |
|---|---|---|
| Tokens in `SharedPreferences` or plain files | Readable local secrets | `flutter_secure_storage` or platform keystores |
| Secrets in source, assets or `--dart-define` | Recoverable from the shipped app | Keep them on a server |
| `badCertificateCallback` returning `true` | No TLS verification | Remove it; pin only with a rotation plan |
| `MethodChannel` handlers trusting arguments | Native code reached with unchecked data | Validate types and values on both sides |
| WebView with unrestricted JavaScript and channels | Web content calls app code | Allowlist origins in the navigation delegate |
| Deep link parameters used for actions | Unauthorized navigation or changes | Validate, require an authenticated confirmation |
| `Process.run(..., runInShell: true)` | Command injection | Argument list without a shell |
| Authorization decided only in the app | Bypassed by calling the API | Enforce on the server |

```dart
// Vulnerable: accepts any certificate
client.badCertificateCallback = (cert, host, port) => true;
```

Usually safe: values rendered by `Text` widgets, which do not interpret markup.

## Scala

| Look for | Risk | Use instead |
|---|---|---|
| `sql"... #$value"` in Slick, `s"..."` passed to a query | SQL injection (`#$` splices text) | `$value` bindings, doobie fragments |
| Anorm or JDBC with string interpolation | SQL injection | `.on(...)`, parameters |
| `scala.xml.XML.loadString` on untrusted XML | External entities, entity expansion, depending on parser settings | A `SAXParserFactory` with DTDs disabled, passed through `XML.withSAXParser` |
| Java serialization, Akka or Pekko Java serializer | Deserialization RCE | Explicit JSON or protobuf codecs |
| `sys.process` with `Seq("sh", "-c", x)` | Command injection | `Seq(binary, arg)` |
| Play `Html(userValue)` | XSS | Default template escaping |
| Play CSRF filter disabled, `+ nocsrf` routes | CSRF | Keep the filter on cookie-authenticated routes |
| `Await.result` without a bound, unbounded `Future` fan-out | Resource exhaustion | Timeouts and bounded parallelism |
| Non-exhaustive match on a role or state | Unhandled case on a security path | Sealed types, deny in the default case |

The Java section also applies.

## Elixir

| Look for | Risk | Use instead |
|---|---|---|
| `String.to_atom` on input | Atom table exhaustion crashes the VM | `String.to_existing_atom` or a mapping |
| `Code.eval_string`, `EEx.eval_string` with input | Code execution | Pattern match on allowed operations |
| `:erlang.binary_to_term` on external data | Unsafe terms; `[:safe]` blocks new atoms but still allows functions | A data format such as JSON, or a non-executable decoder |
| Ecto `fragment` or `Ecto.Adapters.SQL.query` with interpolation | SQL injection | Pinned values `^value`, `?` placeholders |
| Ecto `cast` including `:role` or `:user_id` | Mass assignment | Cast only fields users may set |
| Phoenix `raw/1` | XSS | Default HEEx escaping |
| `:os.cmd`, `System.shell` with input | Command injection | `System.cmd(binary, args)` |
| LiveView `handle_event` without authorization | Events can be sent for any record | Check permission in every event, not only in `mount` |
| ETS `:public` tables, open distribution port or weak cookie | Data tampering, remote code execution across nodes | Restrict access and network exposure |

Usually safe: Ecto query syntax with `^` pins.

## Lua

| Look for | Risk | Use instead |
|---|---|---|
| `load`, `loadstring`, `dofile`, `loadfile` with input | Code execution | Data parsers; if code is required, `load` with text mode and a minimal environment |
| Bytecode accepted by `load` | Sandbox escape or crash | Pass mode `"t"` |
| `os.execute`, `io.popen` | Command injection | Avoid; strictly allowlist arguments |
| `debug`, `package`, `require` reachable in a sandbox | Escape | Expose only the functions needed |
| OpenResty: `ngx.var` or arguments in SQL or Redis scripts | Injection | `ndk.set_var.set_quote_sql_str`, `ARGV` for Redis |
| OpenResty: module-level variables holding request data | Data leaks between requests | `ngx.ctx` or locals |
| `ngx.req.get_headers()` values assumed to be strings | A repeated header becomes a table, bypassing checks | Handle the table case |
| No instruction or memory limit on user scripts | Denial of service | Debug hooks, host limits |

## Perl

| Look for | Risk | Use instead |
|---|---|---|
| Two-argument `open` | Mode characters or pipes in the name run commands | `open(my $fh, '<', $path)` |
| `system` or `exec` with one string, backticks, `qx` | Command injection | List form: `system($bin, @args)` |
| String `eval` | Code execution | Block `eval` for errors only |
| Input interpolated into a regex | ReDoS, changed match logic | `\Q$input\E` |
| DBI queries with interpolation | SQL injection | Placeholders |
| `Storable::thaw`, YAML loaders that build objects | Object injection | `JSON::PP`, safe loaders |
| CGI `param` in list context | Parameter pollution changes arguments | Force scalar context |
| Missing `use strict`, `use warnings`, taint mode on setuid or CGI | Bugs reach sinks unnoticed | Enable them; untaint with narrow patterns |

## PowerShell

| Look for | Risk | Use instead |
|---|---|---|
| `Invoke-Expression`, `iex` with input | Code execution | Call commands directly with parameters |
| `& $command` where the name comes from input | Arbitrary command | Allowlist |
| `[ScriptBlock]::Create($x)`, expandable strings with input | Code execution | `-ArgumentList`, `$using:` for remote values |
| `powershell -Command "... $x"` from another program | Injection through re-parsing | `-File` with arguments |
| `iwr ... \| iex` | Unverified remote code | Download, verify signature or hash |
| Plain-text passwords, `ConvertTo-SecureString -AsPlainText` with literals | Exposed credentials | Secret management module or vault |
| `-SkipCertificateCheck` | No TLS verification | Remove |
| `Join-Path` with input | Traversal | Resolve and check the prefix; prefer `-LiteralPath` |

`-ExecutionPolicy Bypass` is not a security boundary, but in automation it deserves a look at what is being run.

## R

| Look for | Risk | Use instead |
|---|---|---|
| `eval(parse(text = x))` | Code execution | Dispatch on allowed values |
| `source` of a user path or URL | Code execution | Fixed files only |
| `system`, `system2`, `shell` with input | Command injection | Fixed binary, validated arguments, `shQuote` |
| `load`, `readRDS` on untrusted files | Deserialized objects can run code when used | CSV, JSON, Parquet |
| `paste` into SQL | SQL injection | `DBI::dbBind`, `glue::glue_sql` |
| `file.path` with input | Path traversal | `normalizePath` and prefix check |
| Shiny `HTML()` with input | XSS | Default tag escaping |
| Shiny: UI hiding used as access control, shared globals | Missing authorization, data leaks between sessions | Check in the server function; keep state per session |
| Plumber endpoints without a filter for authentication | Open API | Authentication filter on every route |

## SQL

- Parameters bind values only. Table names, column names and sort direction need an allowlist.
- Stored procedures that build dynamic SQL are injectable even when the caller binds parameters.
- Escape `%` and `_` in `LIKE` input when wildcards would widen access or cost.
- Check that application accounts have least privilege and that multi-tenant tables enforce isolation (row-level security or a mandatory tenant filter).
- Read-then-write on balances, stock or coupons needs a transaction with locking or a conditional update.
