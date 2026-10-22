# PHP WATCH

A small, open-source PHP security intelligence dashboard MVP.

## Features
- **Threat Radar:** fetches recent CVE records matching the keyword `PHP` from the official NVD CVE API 2.0, with severity counts, search, filters, publication dates, and an in-app CVE detail panel with NVD-provided descriptions, weakness classifications, and reference links. The official NVD record remains available for verification. The feed loads on page open and can be manually refreshed.
- **Safe Scanner:** locally analyzes HTTP response headers pasted by the user. It makes no network requests and does not exploit or probe any host.
- **Shareable Report:** builds a redacted text report that can be copied or shared.

## Run locally
Requires Node.js 20+.

```bash
npm install
npm run dev
```

Open the local URL printed by Vite.

## Build
```bash
npm run build
npm run preview
```

## Deploy to Railway
1. Push this repository to GitHub.
2. In Railway, choose **New Project → Deploy from GitHub Repo** and select this repo.
3. Railway detects the `Dockerfile` and builds the static site.
4. Open the service **Settings → Networking → Generate Domain**.
5. Open the generated HTTPS URL and test all three tabs.

No API keys or environment variables are required for this MVP. Threat Radar needs an internet connection to load NVD data; if NVD is unavailable or rate-limits requests, the dashboard shows an explicit feed error instead of fake records.

## Scanner scope and limitations
This tool checks only the header text you paste into the browser. It does not fetch the target URL, validate server identity, or prove that a site is secure. Missing headers are recommendations, not proof of a vulnerability. Some headers may be intentionally configured differently depending on application architecture.

For a quick local capture, run this against a site you own or are authorized to assess:

```bash
curl -sSI https://your-domain.example
```

Paste the output into Safe Scanner. Do not paste cookies, authorization headers, session tokens, or other secrets.

## Security and data handling
- No backend and no database.
- No target URL is fetched by the app.
- Report text is generated in the browser.
- Threat Radar displays records from the NVD keyword search API. The keyword `PHP` can match records about other products that mention PHP; verify affected products, versions, and severity on the original CVE record. The feed is periodically fetched, not a real-time attack monitor.
- This project is not affiliated with the PHP project, PHP Foundation, NVD, or any token issuer.

## Data source and freshness
- NVD CVE API 2.0: https://nvd.nist.gov/developers/vulnerabilities
- The client requests the last 120 days of published records matching the keyword `PHP` and shows the time of the last successful refresh.
- No records are hard-coded or presented as live data. A future server-side cache could reduce client-side rate limiting and improve availability.

## Next steps
- Add a small server-side feed aggregator with strict source allowlisting and caching.
- Add tests for header parsing and report generation.
- Add an opt-in public report page only after adding privacy controls and expiry.


## Threat intelligence dashboard updates

- Adds an overview based on the currently loaded NVD result set: severity distribution, loaded record count, critical/high count, product-configuration coverage, and this-month publication count.
- Adds a 30/60/119-day date window, which reloads records from NVD, plus vendor/product text matching in the threat search and product filter.
- Shows vulnerable CPE matches supplied by NVD in each in-app CVE detail panel. NVD CPE matches are not a substitute for checking vendor advisories and fixed versions.
