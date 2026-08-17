# Language-Specific Security Quirks

> **Important:** The examples below are illustrative starting points, not exhaustive. When reviewing code, think like a senior security researcher: consider the language's memory model, type system, standard library pitfalls, ecosystem-specific attack vectors, and historical CVE patterns. Each language has deeper quirks beyond what's listed here.

Different languages have unique security pitfalls. This file covers 20+ languages and frameworks with key security considerations. **Go deeper for the specific language you're working in.**

## Contents
- [JavaScript / TypeScript](#javascript--typescript)
- [Angular](#angular)
- [Python](#python)
- [Java](#java)
- [C# / .NET](#c--net)
- [PHP](#php)
- [Go](#go)
- [Ruby](#ruby)
- [Rust](#rust)
- [Swift](#swift)
- [Kotlin](#kotlin)
- [C / C++](#c--c)
- [Scala](#scala)
- [R](#r)
- [Perl](#perl)
- [Shell (Bash)](#shell-bash)
- [Lua](#lua)
- [Elixir](#elixir)
- [Dart / Flutter](#dart--flutter)
- [PowerShell](#powershell)
- [SQL (All Dialects)](#sql-all-dialects)

---

### JavaScript / TypeScript
**Main Risks:** Prototype pollution, XSS, eval injection
```javascript
// UNSAFE: Prototype pollution — the vector is RECURSIVE merge, not a shallow copy.
// Payload {"__proto__": {"isAdmin": true}} reaches Object.prototype for every object.
deepMerge(config, JSON.parse(body))   // lodash.merge, _.set, hand-rolled merges
// SAFE: reject the dangerous keys, or work on a prototype-less object
for (const k of ["__proto__", "constructor", "prototype"]) delete input[k];
const safe = Object.assign(Object.create(null), validated);

// UNSAFE: eval injection (and its aliases)
eval(userCode); new Function(userCode); setTimeout(userCode, 0);
// SAFE: Never build executable code from user input
```
**Watch for:** `eval()`, `new Function()`, string arguments to `setTimeout`/`setInterval`,
`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write()`, `dangerouslySetInnerHTML`,
`location`/`href` assignment from user input, `__proto__` and `constructor.prototype`,
`postMessage` handlers without an `origin` check.

**Node.js specifically:** `child_process.exec`/`execSync` (use `execFile` with an argv array),
`fs` paths built from user input (traverse with `../`), dynamic `require()`, `vm` used as a
sandbox (it is not one), SSRF via `fetch`/`axios` to a user-supplied URL, and JWT libraries
accepting `alg: none` or a user-chosen algorithm.

---

### Angular

**Main Risks:** Sanitizer bypass, secrets shipped in the bundle, guards mistaken for authorization

Angular escapes by default in templates — `{{ value }}` is safe, and `[innerHTML]` is sanitized.
Almost every Angular XSS is therefore something that **deliberately turned the sanitizer off**,
which makes the review targeted: find the bypasses.

```typescript
// UNSAFE: bypassSecurityTrust* disables sanitization for that value
this.html = this.sanitizer.bypassSecurityTrustHtml(userContent);
// UNSAFE: the classic — user-controlled iframe/script source
this.url = this.sanitizer.bypassSecurityTrustResourceUrl(userUrl);
// SAFE: let Angular sanitize; if you must allow rich text, sanitize server-side
// with an allowlist (DOMPurify) and keep the value going through [innerHTML]
this.html = userContent;   // template: <div [innerHTML]="html"></div>

// UNSAFE: writing to the DOM directly bypasses Angular entirely
this.el.nativeElement.innerHTML = userContent;
// SAFE: Renderer2 with text, or property binding
this.renderer.setProperty(this.el.nativeElement, 'textContent', userContent);
```

```typescript
// UNSAFE: environment files are compiled INTO the browser bundle.
// Anything here is public — "production" does not mean "private".
export const environment = {
  production: true,
  apiKey: 'sk-live-...',          // shipped to every visitor
  dbConnection: '...',
};
// SAFE: the browser holds no secrets. Proxy privileged calls through your backend.
export const environment = { production: true, apiUrl: '/api' };
```

```typescript
// UNSAFE to RELY ON: a route guard is UX, not authorization.
// The user controls the bundle; they can call the API directly.
canActivate(): boolean { return this.auth.isAdmin(); }
// The server must enforce the same rule — see [Authorize] in the C# section.
```

**Watch for:**
- Any `bypassSecurityTrust*` call — each one needs a justification and a sanitized input
- `ElementRef.nativeElement` DOM writes, `document.write`, jQuery mixed into a component
- Secrets, API keys, or connection strings in `environment*.ts`
- Tokens in `localStorage` (readable by any XSS) — prefer `HttpOnly; Secure; SameSite` cookies
- CSRF: `HttpClientXsrfModule` only sends the header; the **backend must validate it**, and it
  only works when the API is same-origin
- JIT compilation / templates built from user input (SSTI); AOT is the default — keep it, it also
  lets your CSP drop `unsafe-eval`
- Source maps enabled in a production build (`ng build` config), exposing full source
- `[href]`/`[src]` bound to user data — Angular blocks `javascript:` in URL context, but not if
  the value was marked trusted first

---

### Python
**Main Risks:** Pickle deserialization, format string injection, SQL/shell injection
```python
# UNSAFE: Pickle RCE
pickle.loads(user_data)
# SAFE: Use JSON or validate source
json.loads(user_data)

# UNSAFE: SQL injection via string interpolation
query = "SELECT * FROM users WHERE name = '%s'" % user_input
# SAFE: Parameterized
cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))

# UNSAFE: Format string injection — user controls the TEMPLATE, not the argument.
# "{u.__class__.__init__.__globals__[SECRET]}" walks attributes and leaks module globals.
user_template.format(u=user)
# SAFE: template is a literal, user data is an argument
"Hello {name}".format(name=user_input)
```
**Watch for:** `pickle`, `yaml.load` without `SafeLoader`, `eval()`, `exec()`, `os.system()`,
`subprocess` with `shell=True`, user-controlled format templates, `jinja2.Template(user_input)`
(SSTI), `__import__`

---

### Java
**Main Risks:** Deserialization RCE, XXE, JNDI injection
```java
// UNSAFE: Arbitrary deserialization
ObjectInputStream ois = new ObjectInputStream(userStream);
Object obj = ois.readObject();

// SAFE: Use allowlist or JSON
ObjectMapper mapper = new ObjectMapper();
mapper.readValue(json, SafeClass.class);
```
**Watch for:** `ObjectInputStream`, `Runtime.exec()`, XML parsers without XXE protection, JNDI lookups

---

### C# / .NET
**Main Risks:** Deserialization, SQL injection, path traversal, overposting, missing authorization

```csharp
// UNSAFE: BinaryFormatter RCE (obsolete since .NET 5, removed in .NET 9)
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);
// UNSAFE: Newtonsoft type handling lets the payload choose the type to instantiate
JsonConvert.DeserializeObject<T>(json,
    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
// SAFE: System.Text.Json, concrete type, no polymorphic binding from the wire
var obj = JsonSerializer.Deserialize<SafeType>(json);
```

```csharp
// UNSAFE: concatenation
var sql = "SELECT * FROM Users WHERE Email = '" + email + "'";
// UNSAFE: FromSqlRaw with an interpolated string is still concatenation
ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'");
// SAFE: FromSqlInterpolated parameterizes the interpolation holes
ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}");
// SAFE: explicit parameters with ADO.NET
cmd.CommandText = "SELECT * FROM Users WHERE Email = @email";
cmd.Parameters.Add(new SqlParameter("@email", SqlDbType.NVarChar, 256) { Value = email });
```

```csharp
// UNSAFE: Path.Combine DISCARDS earlier segments if a later one is rooted.
// userPath = "C:\\Windows\\win.ini" or "/etc/passwd" escapes the base entirely.
var path = Path.Combine(baseDir, userPath);
// SAFE: canonicalize, then verify containment
var full = Path.GetFullPath(Path.Combine(baseDir, userPath));
var root = Path.GetFullPath(baseDir) + Path.DirectorySeparatorChar;
if (!full.StartsWith(root, StringComparison.Ordinal)) return Forbid();
```

```csharp
// UNSAFE: overposting — the binder fills every property the model exposes,
// including IsAdmin, if the request body sends it
public IActionResult Update(User user) { _db.Update(user); ... }
// SAFE: bind to a DTO carrying only what the caller may set
public IActionResult Update(UserUpdateDto dto) { ... }
```

```csharp
// UNSAFE: open redirect — returnUrl may point off-site
return Redirect(returnUrl);
// SAFE: LocalRedirect throws on an absolute URL
return LocalRedirect(returnUrl);

// UNSAFE: predictable — System.Random is not a CSPRNG
var token = new Random().Next().ToString();
// SAFE
var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

// UNSAFE: disables certificate validation globally
ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
```

**ASP.NET Core configuration to verify:**
```csharp
// Deny by default: unauthenticated requests are rejected unless [AllowAnonymous]
builder.Services.AddAuthorization(o =>
    o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
// CSRF on every state-changing MVC action, not per-controller
builder.Services.AddControllersWithViews(o =>
    o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

if (app.Environment.IsDevelopment())
    app.UseDeveloperExceptionPage();   // must stay gated by environment
else { app.UseExceptionHandler("/error"); app.UseHsts(); }
app.UseHttpsRedirection();
```

**Watch for:** `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`,
`JavaScriptSerializer`, `TypeNameHandling` other than `None`, `FromSqlRaw`/`ExecuteSqlRaw` with
interpolation, `@Html.Raw()` in Razor, `Path.Combine` with user input, `[AllowAnonymous]` on
sensitive actions, controllers missing `[Authorize]` where there is no fallback policy,
`ValidateAntiForgeryToken` applied inconsistently, `Process.Start` with `UseShellExecute = true`,
`XmlDocument`/`XmlTextReader` without `XmlResolver = null` and `DtdProcessing.Prohibit` (XXE),
`Regex` on user input without `matchTimeout` (ReDoS), connection strings and keys in
`appsettings.json` or `web.config` committed to git (use User Secrets locally, Key Vault in
production), and ViewState with MAC/encryption disabled or a machine key checked into source.

---

### PHP
**Main Risks:** Type juggling, file inclusion, object injection, weak SQL layer defaults

```php
// UNSAFE: Type juggling — "magic hashes" like "0e123" == "0e456" both cast to float 0
if ($password == $stored_hash) { ... }
// SAFE: Verify against a password hash (constant-time, algorithm-aware)
if (password_verify($password, $stored_hash)) { ... }
// Store with password_hash(); never md5/sha1, never your own salt scheme
$hash = password_hash($password, PASSWORD_DEFAULT);
// Comparing two known strings (tokens, HMACs, webhook signatures):
if (hash_equals($expected_token, $provided_token)) { ... }
```

```php
// UNSAFE: emulated prepares build the query string client-side — with a bad charset
// this reopens injection. Turn emulation off explicitly.
$pdo = new PDO($dsn, $user, $pass);
// SAFE
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
$stmt->execute([$email]);
```

```php
// UNSAFE: File inclusion (LFI/RFI)
include($_GET['page'] . '.php');
// SAFE: Allowlist pages
$allowed = ['home', 'about']; include(in_array($page, $allowed, true) ? "$page.php" : 'home.php');

// UNSAFE: object injection — unserialize() instantiates classes and fires magic
// methods (__wakeup, __destruct), which is how POP-chain RCE works
$obj = unserialize($_COOKIE['data']);
// SAFE: JSON, or forbid class instantiation entirely
$obj = json_decode($_COOKIE['data'], true);
$obj = unserialize($data, ['allowed_classes' => false]);
```

```php
// UNSAFE: escapeshellcmd does NOT make arguments safe (quotes stay exploitable)
system('convert ' . escapeshellcmd($file));
// SAFE: escape each argument, or skip the shell
system('convert ' . escapeshellarg($file) . ' out.png');

// UNSAFE: trusting client-supplied upload metadata — both are attacker-controlled
if ($_FILES['f']['type'] === 'image/png') { ... }
// SAFE: check real content, generate your own name and extension, store outside webroot
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['f']['tmp_name']);
$name = bin2hex(random_bytes(16)) . '.png';   // never trust the original filename
```

```php
// Sessions: regenerate on privilege change, and set cookie flags
session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);
session_regenerate_id(true);   // on login — otherwise session fixation
```

**Watch for:** `==` and `in_array`/`switch` without strict comparison, `include`/`require` with
request data, `unserialize()`, `extract()`, variable variables (`$$var`), `eval()`, `assert()`
with a string, backticks, `preg_replace` with `/e` (legacy), `move_uploaded_file` without content
validation, `header()` with user input (response splitting), `$_REQUEST` (mixes GET/POST/COOKIE),
`display_errors = On` in production, and secrets in `.env` or config files served from the webroot.

**Laravel:** `$guarded = []` or `forceFill` (mass assignment), `DB::raw()` and `whereRaw()` with
interpolation, `{!! !!}` in Blade (unescaped output — `{{ }}` is safe), `APP_DEBUG=true` in
production (Ignition leaks env and config), routes missing `auth`/`can` middleware, and
`Storage::url()` on user-named files.
**Symfony/Twig:** `|raw` filter, Doctrine DQL built by concatenation, and `dev.php`/`_profiler`
reachable in production.

---

### Go
**Main Risks:** Race conditions, template injection, slice bounds
```go
// UNSAFE: Race condition
go func() { counter++ }()
// SAFE: Use sync primitives
atomic.AddInt64(&counter, 1)

// UNSAFE: Template injection
template.HTML(userInput)
// SAFE: Let template escape
{{.UserInput}}
```
**Watch for:** Goroutine data races, `template.HTML()`, `unsafe` package, unchecked slice access

---

### Ruby
**Main Risks:** Mass assignment, YAML deserialization, regex DoS
```ruby
# UNSAFE: Mass assignment
User.new(params[:user])
# SAFE: Strong parameters
User.new(params.require(:user).permit(:name, :email))

# UNSAFE: YAML RCE
YAML.load(user_input)
# SAFE: Use safe_load
YAML.safe_load(user_input)
```
**Watch for:** YAML.load, Marshal.load, eval, send with user input, .permit!

---

### Rust
**Main Risks:** Unsafe blocks, FFI boundary issues, integer overflow in release
```rust
// CAUTION: Unsafe bypasses safety
unsafe { ptr::read(user_ptr) }

// CAUTION: Integer overflow panics in debug, wraps silently in release
// (a literal `255u8 + 1` is a compile error — this only bites on runtime values)
let x: u8 = parse_user_len(input);
let y = x + 1; // panic in debug; wraps to 0 in release (overflow-checks = off)
// SAFE: Be explicit about the overflow case
let y = x.checked_add(1).ok_or(Error::TooLarge)?;
```
**Watch for:** `unsafe` blocks, FFI calls, integer overflow in release builds, `.unwrap()` on untrusted input

---

### Swift
**Main Risks:** Force unwrapping crashes, Objective-C interop
```swift
// UNSAFE: Force unwrap on untrusted data
let value = jsonDict["key"]!
// SAFE: Safe unwrapping
guard let value = jsonDict["key"] else { return }

// UNSAFE: Format string
String(format: userInput, args)
// SAFE: Don't use user input as format
```
**Watch for:** force unwrap (!), try!, ObjC bridging, NSSecureCoding misuse

---

### Kotlin
**Main Risks:** Null safety bypass, Java interop, serialization
```kotlin
// UNSAFE: Platform type from Java
val len = javaString.length // NPE if null
// SAFE: Explicit null check
val len = javaString?.length ?: 0

// UNSAFE: Reflection
clazz.getDeclaredMethod(userInput)
// SAFE: Allowlist methods
```
**Watch for:** Java interop nulls (! operator), reflection, serialization, platform types

---

### C / C++
**Main Risks:** Buffer overflow, use-after-free, format string
```c
// UNSAFE: Buffer overflow
char buf[10]; strcpy(buf, userInput);

// ALSO UNSAFE: strncpy does NOT null-terminate when src >= n
strncpy(buf, userInput, sizeof(buf) - 1);   // buf may be unterminated

// SAFE: snprintf always terminates and reports truncation
if (snprintf(buf, sizeof buf, "%s", userInput) >= (int)sizeof buf) {
    /* input was truncated — decide explicitly, don't ignore */
}

// UNSAFE: Format string
printf(userInput);
// SAFE: Always use format specifier
printf("%s", userInput);
```
**Watch for:** `strcpy`, `strncpy` (no null terminator), `sprintf`, `gets`, `alloca` with user size, pointer arithmetic, manual memory management, integer overflow in size calculations before `malloc`

---

### Scala
**Main Risks:** XML external entities, serialization, pattern matching exhaustiveness
```scala
// UNSAFE: XXE
val xml = XML.loadString(userInput)
// SAFE: Disable external entities
val factory = SAXParserFactory.newInstance()
factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
```
**Watch for:** Java interop issues, XML parsing, `Serializable`, exhaustive pattern matching

---

### R
**Main Risks:** Code injection, file path manipulation
```r
# UNSAFE: eval injection
eval(parse(text = user_input))
# SAFE: Never parse user input as code

# UNSAFE: Path traversal
read.csv(paste0("data/", user_file))
# SAFE: Validate filename
if (grepl("^[a-zA-Z0-9]+\\.csv$", user_file)) read.csv(...)
```
**Watch for:** `eval()`, `parse()`, `source()`, `system()`, file path manipulation

---

### Perl
**Main Risks:** Regex injection, open() injection, taint mode bypass
```perl
# UNSAFE: Regex DoS
$input =~ /$user_pattern/;
# SAFE: Use quotemeta
$input =~ /\Q$user_pattern\E/;

# UNSAFE: open() command injection
open(FILE, $user_file);
# SAFE: Three-argument open
open(my $fh, '<', $user_file);
```
**Watch for:** Two-arg `open()`, regex from user input, backticks, `eval`, disabled taint mode

---

### Shell (Bash)
**Main Risks:** Command injection, word splitting, globbing
```bash
# UNSAFE: Unquoted variables
rm $user_file
# SAFE: Always quote
rm "$user_file"

# UNSAFE: eval
eval "$user_command"
# SAFE: Never eval user input
```
**Watch for:** Unquoted variables, `eval`, backticks, `$(...)` with user input, missing `set -euo pipefail`

---

### Lua
**Main Risks:** Sandbox escape, loadstring injection
```lua
-- UNSAFE: Code injection
loadstring(user_code)()
-- SAFE: Use sandboxed environment with restricted functions
```
**Watch for:** `loadstring`, `loadfile`, `dofile`, `os.execute`, `io` library, debug library

---

### Elixir
**Main Risks:** Atom exhaustion, code injection, ETS access
```elixir
# UNSAFE: Atom exhaustion DoS
String.to_atom(user_input)
# SAFE: Use existing atoms only
String.to_existing_atom(user_input)

# UNSAFE: Code injection
Code.eval_string(user_input)
# SAFE: Never eval user input
```
**Watch for:** `String.to_atom`, `Code.eval_string`, `:erlang.binary_to_term`, ETS public tables

---

### Dart / Flutter
**Main Risks:** Platform channel injection, insecure storage
```dart
// UNSAFE: Storing secrets in SharedPreferences
prefs.setString('auth_token', token);
// SAFE: Use flutter_secure_storage
secureStorage.write(key: 'auth_token', value: token);
```
**Watch for:** Platform channel data, `dart:mirrors`, `Function.apply`, insecure local storage

---

### PowerShell
**Main Risks:** Command injection, execution policy bypass
```powershell
# UNSAFE: Injection
Invoke-Expression $userInput
# SAFE: Avoid Invoke-Expression with user data

# UNSAFE: Unvalidated path
Get-Content $userPath
# SAFE: Validate path is within allowed directory
```
**Watch for:** `Invoke-Expression`, `& $userVar`, `Start-Process` with user args, `-ExecutionPolicy Bypass`

---

### SQL (All Dialects)
**Main Risks:** Injection, privilege escalation, data exfiltration
```sql
-- UNSAFE: String concatenation
"SELECT * FROM users WHERE id = " + userId

-- SAFE: Parameterized query (language-specific)
-- Use prepared statements in ALL cases
```
**Watch for:** Dynamic SQL, `EXECUTE IMMEDIATE`, stored procedures with dynamic queries, privilege grants
