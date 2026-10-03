# Changelog

## 4.4.2

Security and bug-fix release. Drop-in compatible with 4.4.1: no API changes.

### Security

- **Path traversal through malformed UTF-8** ([#106](https://github.com/garycourt/uri-js/issues/106)).
  Invalid and overlong percent-encoded sequences were decoded without validation, so
  `%E0%40%2E` became `.` and `%E0%40%0D%E0%40%0A` became CRLF. With default options,
  `normalize`, `resolve` and `equal` then treated `%E0%40%2E%E0%40%2E` as a `..` segment:
  `normalize("http://example.com/public/%E0%40%2E%E0%40%2E/secret")` returned
  `http://example.com/secret`. Malformed and overlong sequences are now left
  percent-encoded unchanged.
- **Denial of service in `removeDotSegments`** ([#105](https://github.com/garycourt/uri-js/issues/105)).
  A path containing U+2028 or U+2029 made `normalize` (with `iri: true`) and `resolve`
  (with `iri: true, unicodeSupport: true`) loop forever and exhaust memory, crashing the
  process. Calling `removeDotSegments` directly was also affected by `\r`. Default
  options were not affected.
- **`mailto:` parser crashes** ([#103](https://github.com/garycourt/uri-js/issues/103)).
  `URI.parse("mailto:?to")` threw a `TypeError`, as did addresses without `@` when
  `unicodeSupport` is enabled.

### Fixes

- Serializing a `mailto:` address without `@` no longer rewrites it:
  `normalize("mailto:foo")` returned `mailto:fo@foo`.
- 4-byte UTF-8 sequences (e.g. `%F0%9F%98%80`) are no longer decoded into a wrong
  character; they are left percent-encoded.

### Packaging

- `yarn.lock` is no longer published, so dependency scanners stop reporting its stale
  entries against projects that use uri-js ([#102](https://github.com/garycourt/uri-js/issues/102)).
