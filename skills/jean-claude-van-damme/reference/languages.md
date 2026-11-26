# Language Pitfalls

Read only the sections for the languages under review. A match here is a lead: trace it from source to sink and apply the triage rubric in `SKILL.md` before reporting. Code examples are fragments that show the pattern, not complete programs; adapt names, limits and error handling. Some sections also list cases that look dangerous but usually are not.

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

```python
ALLOWED_HOSTS = {"api.example.com"}

# Vulnerable: fetches whatever the caller names, following redirects
requests.get(user_url)

# Fixed for a known set of destinations
def fetch(user_url: str) -> bytes:
    url = urlsplit(user_url)
    if url.scheme != "https" or url.hostname not in ALLOWED_HOSTS or url.port not in (None, 443):
        raise ValueError("destination not allowed")
    # Rebuild from validated parts so a second parser cannot read another host
    safe_url = urlunsplit(("https", url.hostname, url.path, url.query, ""))
    with requests.get(safe_url, timeout=5, allow_redirects=False, stream=True) as response:
        response.raise_for_status()
        body = response.raw.read(MAX_BYTES + 1, decode_content=True)
    if len(body) > MAX_BYTES:
        raise ValueError("response too large")
    return body
```

### File uploads

- Check content, not only extension or `Content-Type`, and generate the stored name on the server.
- Store outside the web root; serve with `Content-Disposition: attachment` or from a separate origin.
- Limit size, count and decompressed size; treat SVG and HTML as active content.

```python
# Vulnerable: the client chooses the name, type and a web-served location
upload.save(os.path.join("static/uploads", upload.filename))

# Fixed
SIGNATURES = {b"\x89PNG\r\n\x1a\n": ".png", b"\xff\xd8\xff": ".jpg"}

def store(upload, upload_dir: Path) -> str:
    data = upload.stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("file too large")
    suffix = next((ext for magic, ext in SIGNATURES.items() if data.startswith(magic)), None)
    if suffix is None:
        raise ValueError("type not allowed")
    name = secrets.token_hex(16) + suffix  # server-generated name
    (upload_dir / name).write_bytes(data)  # directory outside the web root
    return name
```

A matching signature does not prove the file is harmless. Re-encode images when the risk justifies it.

### Comparing secrets

Tokens, API keys and webhook signatures need a constant-time comparison: `crypto.timingSafeEqual`, `hmac.compare_digest`, `MessageDigest.isEqual`, `CryptographicOperations.FixedTimeEquals`, `subtle.ConstantTimeCompare`, `hash_equals`. Verify webhook signatures over the raw body and check the timestamp to limit replay.

```js
// Vulnerable: early-exit comparison, computed over re-serialized JSON, no replay window
if (signature === hmac(JSON.stringify(req.body))) handle(req.body);

// Fixed (adapt the signed string to the provider's format)
const expected = crypto
  .createHmac("sha256", secret)
  .update(`${timestamp}.`)
  .update(rawBody)
  .digest();
const received = Buffer.from(signatureHex, "hex");
const fresh = Math.abs(Date.now() / 1000 - Number(timestamp)) < 300;
if (!fresh || received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
  return res.sendStatus(401);
}
```

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

```js
// Vulnerable: the query value reaches a shell
exec(`convert ${req.query.file} out.png`);

// Fixed: no shell, and "./" stops the name being read as an option or format prefix
const name = path.basename(String(req.query.file));
execFile("convert", [`./${name}`, "out.png"], { cwd: WORK_DIR, timeout: 10_000 });
```

```js
// Vulnerable: "../" in the parameter leaves ROOT
res.sendFile(path.join(ROOT, req.params.name));

// Fixed: ROOT is already absolute (path.resolve)
const target = path.resolve(ROOT, req.params.name);
if (!target.startsWith(ROOT + path.sep)) return res.sendStatus(404);
res.sendFile(target); // if users can create symlinks, compare fs.realpath results
```

```tsx
// Vulnerable: a "javascript:" value runs when clicked
<a href={profile.website}>Website</a>

// Fixed
function webUrl(value: string): string | undefined {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}
<a href={webUrl(profile.website)} rel="noopener noreferrer">Website</a>
```

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
# Vulnerable: shell injection and object construction from input
subprocess.run(f"git log {branch}", shell=True)
settings = yaml.load(body, Loader=yaml.Loader)

# Fixed
if branch.startswith("-"):
    raise ValueError("invalid branch")
subprocess.run(["git", "log", branch, "--"], check=True, timeout=10)
settings = yaml.safe_load(body)
```

```python
# Vulnerable: an absolute or "../" name escapes the directory
open(os.path.join("/srv/files", name))
tarfile.open(archive).extractall(dest)

# Fixed
base = Path("/srv/files").resolve()
target = (base / name).resolve()
if not target.is_relative_to(base):
    raise PermissionError(name)
with tarfile.open(archive) as tar:
    tar.extractall(dest, filter="data")  # also limit total size and member count
```

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

```java
// Vulnerable: default settings may resolve external entities
Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(input);

// Fixed: refuse DOCTYPE altogether
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
Document safeDoc = factory.newDocumentBuilder().parse(input);
```

```kotlin
// Vulnerable: a string template builds the query
connection.createStatement().executeQuery("SELECT id FROM users WHERE name = '$name'")

// Fixed
connection.prepareStatement("SELECT id FROM users WHERE name = ?").use { statement ->
    statement.setString(1, name)
    statement.executeQuery().use { rows -> readIds(rows) }
}
```

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

```csharp
// Vulnerable: raw SQL with interpolation, and a rooted name replaces the base path
db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'");
var path = Path.Combine(uploadRoot, fileName);

// Fixed: FromSql turns each interpolated value into a parameter
db.Users.FromSql($"SELECT * FROM Users WHERE Name = {name}");

var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(uploadRoot))
           + Path.DirectorySeparatorChar;
var full = Path.GetFullPath(Path.Combine(root, fileName));
if (!full.StartsWith(root, StringComparison.Ordinal)) return NotFound();
```

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

```go
// Vulnerable
rows, err := db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
file, err := os.Open(filepath.Join(base, userPath))

// Fixed (placeholder syntax depends on the driver; OpenInRoot needs Go 1.24+)
rows, err := db.QueryContext(ctx, "SELECT id FROM users WHERE name = $1", name)
file, err := os.OpenInRoot(base, userPath)
```

```go
// Checks the address actually being dialed, including after redirects
dialer := &net.Dialer{
	Timeout: 5 * time.Second,
	Control: func(_, address string, _ syscall.RawConn) error {
		addrPort, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		ip := addrPort.Addr().Unmap()
		// Add other internal ranges used in your environment, such as 100.64.0.0/10
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return errors.New("blocked address")
		}
		return nil
	},
}
client := &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{DialContext: dialer.DialContext}, // no environment proxy
}
```

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

```php
// Vulnerable: loose comparison of fast hashes, and no ownership check
if (md5($_POST['password']) == $user['hash']) { login($user); }
$post = $pdo->query("SELECT * FROM posts WHERE id = " . $_GET['id']);

// Fixed
if (password_verify($_POST['password'] ?? '', $user['hash'])) {
    session_regenerate_id(true);
    login($user);
}
$statement = $pdo->prepare('SELECT * FROM posts WHERE id = ? AND owner_id = ?');
$statement->execute([$_GET['id'] ?? 0, $currentUserId]);
```

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

```ruby
# Vulnerable
User.where("email = '#{params[:email]}'")
@user.update(params[:user].permit!)
redirect_to params[:next]

# Fixed
User.where(email: params[:email].to_s)
@user.update(params.require(:user).permit(:name, :email))
target = params[:next].to_s
local = target.match?(%r{\A/(?![/\\])[^\\\r\n\t]*\z})
redirect_to(local ? target : root_path)
```

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

```rust
// Vulnerable: the product can wrap in release builds, and slicing can panic
let total = count * item_size;
let payload = &buffer[..total];

// Fixed
let total = count.checked_mul(item_size).ok_or(ParseError::TooLarge)?;
let payload = buffer.get(..total).ok_or(ParseError::Truncated)?;
```

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

```c
/* Vulnerable: size overflow, unbounded copy, attacker-controlled format */
item_t *items = malloc(count * sizeof(item_t));
sprintf(path, "/data/%s", name);
printf(name);

/* Fixed (path is a local char array; validate name against traversal too) */
item_t *items = calloc(count, sizeof *items); /* calloc rejects overflow */
if (items == NULL) return -1;
int written = snprintf(path, sizeof path, "/data/%s", name);
if (written < 0 || (size_t)written >= sizeof path) {
    free(items);
    return -1;
}
printf("%s\n", name);
```

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

```bash
# Vulnerable: word splitting, traversal, and code execution through arithmetic
rm -rf $BUILD_DIR/$name
[[ $retries -gt 5 ]] && exit 1

# Fixed
set -euo pipefail
[[ $name =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || exit 1
rm -rf -- "${BUILD_DIR:?}/$name"
[[ $retries =~ ^[0-9]+$ ]] || exit 1
if (( 10#$retries > 5 )); then exit 1; fi
```

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

```swift
// Vulnerable: stored in a readable preferences file
UserDefaults.standard.set(token, forKey: "authToken")

// Fixed
let base: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.app",
    kSecAttrAccount as String: "authToken",
]
SecItemDelete(base as CFDictionary)
var item = base
item[kSecValueData as String] = Data(token.utf8)
item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
let status = SecItemAdd(item as CFDictionary, nil)
guard status == errSecSuccess else { throw KeychainError(status: status) }
```

```xml
<!-- Vulnerable: cleartext traffic, backups, and a screen any app can open -->
<application android:usesCleartextTraffic="true" android:allowBackup="true">
    <activity android:name=".AdminActivity" android:exported="true" />
</application>

<!-- Fixed -->
<application android:usesCleartextTraffic="false" android:allowBackup="false">
    <activity android:name=".AdminActivity" android:exported="false" />
</application>
```

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
// Vulnerable: accepts any certificate and stores the token in plain preferences
client.badCertificateCallback = (cert, host, port) => true;
await prefs.setString('authToken', token);

// Fixed: keep default certificate validation and use platform secure storage
const storage = FlutterSecureStorage();
await storage.write(key: 'authToken', value: token);
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

```scala
// Vulnerable: #$ splices raw text into the statement
sql"SELECT id FROM users WHERE name = '#$name'".as[Long]

// Fixed: $ creates a bind parameter
sql"SELECT id FROM users WHERE name = $name".as[Long]
```

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

```elixir
# Vulnerable: unbounded atom creation, and users can set their own role
role = String.to_atom(params["role"])
cast(user, params, [:name, :email, :role])

# Fixed
def parse_role("viewer"), do: {:ok, :viewer}
def parse_role("editor"), do: {:ok, :editor}
def parse_role(_), do: :error

def profile_changeset(user, params), do: cast(user, params, [:name, :email])
```

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

```lua
-- Vulnerable: runs any expression the caller sends
local result = load("return " .. input)()

-- Fixed: the caller picks an operation and supplies data
local operations = {
  double = function(n) return n * 2 end,
  negate = function(n) return -n end,
}
local function apply(name, raw)
  local operation, number = operations[name], tonumber(raw)
  if not operation or not number then return nil, "invalid request" end
  return operation(number)
end
```

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

```perl
# Vulnerable: a name such as "id |" runs a command
open(FH, $filename);
system("gzip $filename");

# Fixed
die "invalid name\n" unless $filename =~ /\A[\w-][\w.-]*\z/;
open(my $fh, '<', "$base/$filename") or die "open failed: $!";
system('gzip', '--', "$base/$filename") == 0 or die "gzip failed\n";
```

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

```powershell
# Vulnerable: input is parsed as code
Invoke-Expression "Get-Service $Name"

# Fixed: validated parameter, no re-parsing
function Get-AppService {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9_-]+\z')]
        [string]$Name
    )
    Get-Service -Name $Name
}
```

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

```r
# Vulnerable
result <- eval(parse(text = input$formula))
dbGetQuery(con, paste0("SELECT * FROM users WHERE name = '", input$name, "'"))

# Fixed (placeholder syntax depends on the database driver)
metrics <- list(mean = mean, median = median)
stopifnot(length(input$metric) == 1, input$metric %in% names(metrics))
result <- metrics[[input$metric]](values)
dbGetQuery(con, "SELECT * FROM users WHERE name = ?", params = list(input$name))
```

## SQL

- Parameters bind values only. Table names, column names and sort direction need an allowlist.
- Stored procedures that build dynamic SQL are injectable even when the caller binds parameters.
- Escape `%` and `_` in `LIKE` input when wildcards would widen access or cost.
- Check that application accounts have least privilege and that multi-tenant tables enforce isolation (row-level security or a mandatory tenant filter).
- Read-then-write on balances, stock or coupons needs a transaction with locking or a conditional update.

```sql
-- PostgreSQL. Vulnerable form inside a procedure:
--   EXECUTE 'SELECT * FROM ' || tbl || ' WHERE owner_id = ' || who;

-- Fixed: allowlisted and quoted identifier, bound value
CREATE FUNCTION owned_rows(tbl text, who text) RETURNS SETOF jsonb
LANGUAGE plpgsql AS $$
BEGIN
  IF tbl NOT IN ('orders', 'invoices') THEN
    RAISE EXCEPTION 'table not allowed';
  END IF;
  RETURN QUERY EXECUTE
    format('SELECT to_jsonb(t) FROM %I AS t WHERE t.owner_id::text = $1', tbl)
    USING who;
END
$$;
```
