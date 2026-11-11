# CT Search

A free, single-page Certificate Transparency search. Live at [ct.hbenali.ovh](https://ct.hbenali.ovh).

No backend, no build step, no dependencies: static HTML, CSS and one small script calling public CT search APIs from the browser.

## Features

- **Certificates** logged for a domain and all its subdomains: names (CN and SANs), issuer, not-before / not-after, serial
- **Flags** for expired certificates and certificates expiring within 30 days
- **Unique hostnames**: de-duplicated list of every name seen under the domain, wildcards flagged, with counts
- **Filter** box, chunked rendering (100 rows at a time) so thousands of results do not freeze the page
- **CSV copy** for the certificates and for the hostnames (formula-injection safe)
- Strict domain validation before any URL is built; `?domain=example.com` runs a search on load
- Cross-links to the SSL, CAA, DNSSEC, RDAP, MX, SPF, DMARC and IP tools
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP (`script-src 'self'`)

## Data sources and limits

Both sources were tested from a browser page and return `Access-Control-Allow-Origin: *`:

- [crt.sh](https://crt.sh) (Sectigo): primary. Free, but often slow or overloaded on big domains (5xx or timeouts).
- [Cert Spotter](https://sslmate.com/certspotter) (SSLMate): fallback. Free tier of about 10 requests per hour per IP; gives no serial numbers or common names.

If both fail the page says so and shows a `curl` command to run instead. Only certificates a CA logged in CT appear.

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080/?domain=example.com
```

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
