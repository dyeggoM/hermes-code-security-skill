# Web hardening: gap table and the mechanics behind it

Depth for the "requirements handout" pass in `SKILL.md`. The rule is there; this is how each row is
implemented and how it is proven, so a second handout round on the same stack starts from working
code instead of rediscovering the traps. Nothing here depends on a particular project: substitute
your proxy, your policy and your document paths.

## Gap table

One row per requirement, and the table itself is the deliverable before any edit:

```
R1.1 HTTPS redirect   -> proxy site conf:6 `return 301 https://$host$request_uri`    ok
R2.1 HSTS             -> app middleware only, gated on env == production             partial
R2.6 CSP              -> <meta> in one of three HTML docs, script-src 'unsafe-inline'
R9.1 security.txt     -> absent                                                      missing
R1.3 cert chain       -> not verifiable from this workstation                         n/a
```

Report the `ok` rows. They are the argument that the remaining list is short, and they stop the next
session re-proposing what exists.

## Edge headers: the two traps

1. **A proxy does not inherit.** Anything the reverse proxy serves itself — static files, redirects,
   error pages — never reaches the application's middleware, so headers set only in the framework are
   absent exactly where nobody is watching. Put them in the proxy.
2. **`add_header` in a `location` cancels every inherited `add_header` from the `server` block.** A
   site conf with one `location /static/ { add_header Cache-Control …; }` silently drops HSTS from
   static assets. Fix shape: a snippet included in the `server` block *and* in every `location` that
   declares its own `add_header`.

```nginx
# snippets/security-headers.conf — included in server 443 and in every location with add_header
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Permissions-Policy "camera=(), geolocation=(), payment=(), microphone=(self)" always;
# Headers the app already emits: hide them, or the response carries two values and the browser
# applies the most restrictive one, not the one you declared at the edge.
proxy_hide_header Strict-Transport-Security;
proxy_hide_header X-Content-Type-Options;
proxy_hide_header Referrer-Policy;
proxy_hide_header Permissions-Policy;
```

`always` is not optional: a 404 or a 500 is still a rendered document. When the proxy is not installed
on the box, verify statically — count the includes and assert the `server` block plus every
`add_header`-bearing location carries one — rather than claiming `nginx -t` passed.

Admin and app paths get `X-Robots-Tag: noindex, nofollow`; the public site must stay indexable, so do
not put it at `server` level.

## CSP as a header, with hashes

A `<meta http-equiv="Content-Security-Policy">` only covers the document that carries it and only from
the point the parser reads it. Emit the policy as a response header for `text/html`, from a pure
function so it is testable without a server, and keep any existing meta byte-identical.

Per-document policies when one document loads a third-party SDK: `script-src 'self' 'sha256-…'
https://vendor.example` for that document, `script-src 'self' 'sha256-…'` for the rest. Dropping
`'unsafe-inline'` from `script-src` means hashing every inline script:

```python
import base64, hashlib, re, pathlib
txt = pathlib.Path("app/static/index.html").read_text(encoding="utf-8")
for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", txt, re.S):
    print("sha256-" + base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode())
```

Hash the exact bytes between the tags, no trimming. Recompute it yourself after the change — a stale
hash fails no test and blanks the page. `style-src 'unsafe-inline'` is often unavoidable (inline
`style=` attributes, styles injected by the bundle): keep it and write the reason in the policy, do
not launder it by calling it temporary.

A third-party script pinned with `integrity=` is weaker than vendoring it into the static tree and
serving it from `'self'`: the SRI hash protects against a changed file, not against an unavailable or
slow CDN, and the vendored copy lets the CSP drop the vendor host entirely.

## The cheap rows

- **`/.well-known/security.txt`**: `Contact`, `Expires` (RFC 9116 wants an ISO timestamp in the
  future), `Policy`, `Preferred-Languages`. Serve `text/plain; charset=utf-8`, no long cache. A test
  that parses it and asserts `Expires` is still in the future keeps it from rotting.
- **Errors**: a real 404 with a stable JSON shape, and a catch-all that returns a correlation id while
  the traceback goes to the log only. Assert the body contains neither the exception text nor a
  filesystem path.
- **Data export**: an authenticated endpoint that selects every table `WHERE user_id = <session user>`
  (never the id from the body), returns `Content-Disposition: attachment` with `no-store`, and excludes
  credential material. Prove isolation with two seeded users, not one.
- **Certificate expiry**: `openssl s_client … | openssl x509 -noout -enddate`, then
  `days = (end_epoch - now + 86399) // 86400` — ceiling, because truncation reports "expires in 30
  days" as 29 and moves an alert a day early. Alert at most once per day, and let a missing `openssl`
  log once without killing the healthcheck.

## What a workstation cannot answer

Certificate chain validity, DNS, TLS termination settings and anything a load balancer adds. Mark those
`n/a` with the reason instead of `ok`, and leave the check as a script the operator can run — a row
marked `ok` on unverified territory is worse than an honest hole in the table.
