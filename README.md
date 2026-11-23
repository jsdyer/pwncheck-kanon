# Password Exposure Check

A private-by-design browser utility for comparing a password against [Have I Been Pwned's Pwned Passwords](https://haveibeenpwned.com/Passwords). No account, key, backend or fixed password list is required. Source and local assets are published as a static GitHub Pages application at `/pwncheck-kanon/`.

<!-- coolcode:guide -->
Enter a password and explicitly choose **Check exposure**. Only the first five SHA-1 hash characters go to Pwned Passwords; the browser compares the returned range locally and clears the input after a successful check. A missing match does not prove the password is safe, and a match does not identify an account or a particular breach. Clear everything removes this tab's input and result.
<!-- /coolcode:guide -->

## How it works

1. The browser encodes the exact input as UTF-8, without trimming, normalizing or changing case, and uses Web Crypto to calculate SHA-1.
2. After an explicit submit only, it sends `GET https://api.pwnedpasswords.com/range/{first-five-hex-characters}` with `Add-Padding: true`. It sends no password, full hash, email address, request body or API key. Browser-controlled User-Agent headers are left alone.
3. Returned hash suffixes are compared in memory. Zero-count padding is discarded. Malformed, empty, oversized, unavailable or timed-out responses are errors, never reassuring no-match verdicts.
4. The displayed occurrence count comes from the provider's dataset. It does not count unique people or breaches. SHA-1 is only the provider's lookup format, not a password-storage recommendation.

## Privacy and boundaries

There is no analytics, visit-counter script, remote font, remote image, external JavaScript, service worker, localStorage, sessionStorage, cookie, exported report, saved history or shareable result URL. The only automatic application fetch is its local configuration. API requests start only after Check; typing, toggling visibility and focus changes never start them. Password input has no form `name`, and a restrictive Content Security Policy prevents normal form submission. The standard CoolCode report link carries only the tool ID, never the input or result.

The template's `VISIT_COUNTER` placeholder and builder injection are intentionally removed from this repo. A password-entry tool should not load that extra script. The corresponding builder test explicitly enforces its absence while preserving the issue link.

The request omits credentials and referrers, disables browser fetch caching, and rejects redirects. Both editing and Clear abort active work; clearing during hashing prevents a later API request. A successful check clears the input, and navigating away or restoring the page from the back/forward cache clears visible state. The tool does not promise to overwrite every JavaScript string in browser memory, undo an already-sent request, control password managers/extensions, or remove network/developer-tools records. The provider and its CDN can observe the IP address, requested prefix and normal connection metadata. This is data minimization, not perfect anonymity.

The page does not read unrelated CoolCode storage and cannot control other pages or scripts injected by a hosting proxy. Hosting must preserve the no-analytics/no-injected-script boundary. Visitors should review the source and trust their browser before entering sensitive information. Prefer testing the public example `password` while evaluating the tool; it is not automatically entered or checked.

## Expand or customize

Edit `web/config.json` to change:

| Setting | Default | Meaning |
| --- | --- | --- |
| `timeoutMs` | `15000` | Whole-check timeout; validated from 1–60 seconds. |
| `maxPasswordBytes` | `4096` | Maximum exact UTF-8 input size, up to 65536 bytes. |
| `maxResponseBytes` | `1048576` | Streaming response limit; 40000–2097152 bytes. |

There is no list of sample passwords, domains or accounts to expand: every entered password uses the same explicit range-check flow. `web/model.mjs` contains hashing, strict request construction and response comparison; `web/app.mjs` handles consent-by-click, cancellation and display; `web/style.css` and `web/tokens.css` control appearance. Do not add full-hash requests, type-ahead checks, analytics or persistence. Keep the API host in code and the CSP allowlist together if the provider ever changes; arbitrary API endpoints are deliberately not configurable because they would receive sensitive prefixes.

To publish a change, edit the configuration/source, run the checks below, commit and push to `main`. The existing Pages workflow tests and builds before deployment. There is no scheduled collector and no required GitHub secret. Add enhancements as local processing where possible and update this README when inputs or interpretation change.

## Development and verification

```sh
node --test tests/*.test.mjs
python3 -m unittest discover -s tests -v
python3 scripts/build.py
```

Node tests cover exact UTF-8/SHA-1 behavior, known public vectors, request minimization, padding, malformed data, size limits, errors and cancellation. The build is offline and copies only `web/` to ignored `dist/`. `tests/browser_smoke.py` runs in GitHub Actions with Chromium at a project subpath, uses deterministic intercepted provider responses for the public `password` example, asserts no third-party requests before explicit Check, verifies the sole outbound five-character request and padding header, checks reset/error/no-match states and absence of persistence, and saves desktop/390px screenshots. It never sends real passwords or depends on live provider uptime.

## Source and provider notes

Reviewed 2026-11-23:

- [Official range API, padding, incremental-search guidance and CORS](https://haveibeenpwned.com/API/v3#PwnedPasswords).
- [Provider confirmation: free Pwned Passwords integration, no subscription or licensing requirement](https://support.haveibeenpwned.com/hc/en-au/articles/15316377846671-I-wish-to-use-the-Pwned-Passwords-API-How-can-I-get-started).
- [HIBP privacy policy](https://haveibeenpwned.com/Privacy) and [terms of use](https://haveibeenpwned.com/TermsOfUse).

A live GET using only the documented public `password` test vector's prefix (`5BAA6`) returned HTTP 200, `Access-Control-Allow-Origin: *` and the expected matching suffix. A HEAD request returned 405; this app uses GET. Response lengths can exceed older documentation examples, so the parser has a byte limit rather than a fixed record-count assumption. Browser/CORS validation is also part of deployment review. No real user secret was used for implementation tests.

This tool checks password exposure for the visitor's own benefit. It does not access HIBP's account, email, domain or stealer-log APIs and is not a breach notification service.
