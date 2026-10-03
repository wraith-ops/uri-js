# Security advisory: uri-js ≤ 4.4.1

**Published:** 2026-10-04
**Affected:** `uri-js` ≤ 4.4.1 (all releases of the original package; verified against 4.4.1)
**Fixed in:** `@wraith-ops/uri-js` 4.4.2
**CVE:** none assigned yet

The original `uri-js` package is unmaintained and will not get a fix. Projects that depend on it, usually
indirectly through `ajv@6`, `eslint@8` or webpack tooling, can switch every copy with one override:

```json
"overrides": { "uri-js": "npm:@wraith-ops/uri-js@^4.4.2" }
```

4.4.2 has the same API as 4.4.1. See [How the fix was verified](#how-the-fix-was-verified).

---

## 1. Path traversal through malformed UTF-8 percent-encoding

**Default options affected: yes.** Upstream report: [garycourt/uri-js#106](https://github.com/garycourt/uri-js/issues/106) (decoding behaviour).
The traversal impact through `normalize`, `resolve` and `equal` described below is new in this advisory.

### Cause

`pctDecChars` decodes multi-byte percent-encoded UTF-8 by masking bits, without checking that the
continuation bytes are valid. A malformed sequence whose "continuation" byte is really an ASCII byte
therefore decodes to an ASCII character:

| Input | 4.4.1 output | `decodeURIComponent` |
|---|---|---|
| `%E0%40%2E` | `.` | throws `URIError` |
| `%E0%40%0D%E0%40%0A` | `\r\n` | throws `URIError` |
| `%E0%80%AE` (overlong `.`) | `.` | throws `URIError` |

### Impact

During normalization uri-js decodes any percent-encoded sequence that turns into an *unreserved*
character. `.` is unreserved, so a malformed sequence becomes a literal dot, and the dot-segment
removal step then resolves the resulting `..`:

```js
const URI = require("uri-js"); // 4.4.1, default options

URI.normalize("http://example.com/public/%E0%40%2E%E0%40%2E/secret");
// → "http://example.com/secret"

URI.equal("http://example.com/public/%E0%40%2E%E0%40%2E/secret", "http://example.com/secret");
// → true

URI.resolve("http://a/b/c/", "%E0%40%2E%E0%40%2E/%E0%40%2E%E0%40%2E/etc/passwd");
// → "http://a/etc/passwd"
```

Code that uses uri-js to normalize, resolve or compare URLs before an allow-list or path check can be
bypassed. A URL that looks like it stays under `/public/` normalizes to a path outside it. Other URL
parsers, including WHATWG `URL`, don't treat these bytes as dots, so a check made with one parser and an
action taken with the other may disagree.

`unescapeComponent` is affected the same way, which allows CRLF and `/` injection where its output
reaches headers or paths.

### Fix

Continuation bytes are validated and overlong forms are rejected. A malformed sequence is left
percent-encoded exactly as it was received. Valid UTF-8 decodes as before.

---

## 2. Denial of service in `removeDotSegments`

**Default options affected: no.** Upstream report: [garycourt/uri-js#105](https://github.com/garycourt/uri-js/issues/105).

The segment regex used `(?:.|\n)`, and in JavaScript `.` does not match U+2028, U+2029 or `\r`. For those
characters the regex matched an empty string, so the loop never advanced and pushed to an array until
the process ran out of memory and aborted. A single short IRI is enough:

| Call (4.4.1) | Result |
|---|---|
| `normalize("http://a/b c/../d", {iri: true})` | process crash (out of memory) |
| `resolve("http://a/b/", "x y/../z", {iri: true, unicodeSupport: true})` | process crash (out of memory) |
| `removeDotSegments("/a\rb")` | process crash (out of memory) |
| Same inputs with default options | not affected (characters are percent-encoded first) |

`ajv@6` uses default options and is not exposed through schema `$id` or `$ref` handling.

---

## 3. Uncaught exceptions in the `mailto:` handler

Upstream report: [garycourt/uri-js#103](https://github.com/garycourt/uri-js/issues/103), plus related cases found while fixing it.

- `URI.parse("mailto:?to")` (a `to` header without a value) throws a `TypeError` with default options.
- With `unicodeSupport: true`, an address without `@` (`mailto:foo`) also throws.
- Serializing an address without `@` rewrites it: `normalize("mailto:foo")` returns `mailto:fo@foo`.

Any server that passes request-derived URIs to `URI.parse` without a `try`/`catch` can be crashed by
one request.

---

## Also fixed

- The published package included a stale `yarn.lock`, which made dependency scanners report
  vulnerabilities in projects using uri-js ([#102](https://github.com/garycourt/uri-js/issues/102)).
  It is no longer published.

Not a uri-js issue: the `punycode` deprecation warning (DEP0040) attributed to uri-js in
[#96](https://github.com/garycourt/uri-js/issues/96) and [#100](https://github.com/garycourt/uri-js/issues/100).
The package's main entry bundles its own punycode and never loads Node's built-in module.

---

## How the fix was verified

- Regression tests for every case above, run against both the normal and the minified build.
- A differential test that ran 20,000 generated URIs through 30 operations (`parse`, `normalize`,
  `serialize`, `resolve`, `unescapeComponent`, `escapeComponent` under 5 option sets) on 4.4.1 and
  4.4.2. Each of the roughly 500,000 outputs is either identical or differs only for malformed or
  4-byte UTF-8 input, or for `mailto:` input that crashed or was corrupted in 4.4.1.
- `ajv@6.15` and `eslint@8.57`, run with the override above.
- `dist/` is rebuilt from source in CI on Node 18–24 and must match the committed build byte for byte.

## Credits

- [@waydeshi](https://github.com/waydeshi) reported the decoding issue (#106) and the loop (#105).
- [@August829](https://github.com/August829) reported the mailto crash (#103).
- [@BjoernSieckmannBS](https://github.com/BjoernSieckmannBS) reported the published `yarn.lock` (#102).
- Path traversal impact analysis, fixes and release: [wraith-ops](https://github.com/wraith-ops).
