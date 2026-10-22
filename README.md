# PHP WATCH

A small, open-source PHP security intelligence dashboard MVP.

## Features
- **Threat Radar:** direct links to primary security sources. This starter intentionally does not invent or seed unverified vulnerability claims.
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

No API keys or environment variables are required for this MVP.

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
- Threat Radar links out to primary sources; confirm details on the source before acting.
- This project is not affiliated with the PHP project, PHP Foundation, NVD, or any token issuer.

## Next steps
- Add a small server-side feed aggregator with strict source allowlisting and caching.
- Add tests for header parsing and report generation.
- Add an opt-in public report page only after adding privacy controls and expiry.
