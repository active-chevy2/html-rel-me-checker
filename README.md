# HTML `rel="me"` Checker

<a href="https://www.aihonestybadge.com" target="_blank" rel="noopener"><img src="https://www.aihonestybadge.com/badges/ai-generated-small.svg" alt="AI Generated" height="20"></a>

> This content has been generated with the assistance of AI. We kindly ask that anyone who feels uncomfortable with AI or its users to please refrain from engaging. Thank you for your understanding.

A lightweight, self-hosted web application that inspects any public webpage for `<a>` and `<link>` elements containing `rel="me"`. Useful for verifying IndieWeb, Mastodon, and Fediverse profile links.

Built with zero external `npm` dependencies using native Node.js 22 APIs and vanilla HTML/CSS/JavaScript.

## Features

- **Server-Side Fetching:** Avoids browser CORS restrictions by fetching target HTML on the server, with support for `gzip`, `deflate`, and `br` responses.
- **Self-Hosted Anti-Bot & CAPTCHA:** Protects `/api/check` with a built-in SVG math challenge, HMAC-SHA256 signed single-use tokens, minimum interaction delay checks, and a hidden honeypot field—with zero external third-party scripts.
- **Complete Tag Inspection:** Detects `rel="me"` (including multi-value attributes such as `rel="me nofollow"`) across both `<a>` and `<link>` elements, including `title` and `type` metadata.
- **Relative & `<base>` URL Resolution:** Resolves relative `href` paths against the page's `<base href>` (if present) and final redirected URL.
- **Input Normalisation:** Automatically prepends `https://` if no scheme is entered (including `domain:port` inputs) and supports form submission via the **Enter** key.
- **One-Click Copy:** Copy any extracted `rel="me"` URL directly to your clipboard (with HTTP fallback for local network deployments).
- **Responsive Dark/Light UI:** Adapts automatically to system colour scheme preferences.
- **Hardened Security:** Includes pinned-DNS SSRF protection, redirect hop limits, response size caps, per-IP rate limiting, request timeouts, CSP headers, and XSS-safe DOM rendering.

## Project Structure

```text
.
├── .dockerignore
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── index.html
├── README.md
└── server.js

```

## Quick Start (Docker Compose)

1. Copy the example environment file and adjust ports if needed:
```bash
cp .env.example .env

```


2. Build and start the container:
```bash
docker compose up -d --build

```


3. Open `http://localhost:8080` in your browser.

> **Reverse Proxy / PaaS Deployment (e.g. Coolify, Caddy, Nginx):** Point your proxy to container port `3000` (or whichever value you set for `CONTAINER_PORT`) and set `TRUST_PROXY=true` so rate limiting identifies client IPs accurately. A `/health` endpoint is built in for automated health checks.

## Running Locally (Without Docker)

Requires **Node.js 22** or newer.

```bash
PORT=3000 node server.js

```

Then visit `http://localhost:3000`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `HOST_PORT` | `8080` | Port exposed on the host machine by Docker Compose. |
| `CONTAINER_PORT` | `3000` | Internal port the Node.js server listens on inside the container. |
| `PORT` | `3000` | Application listening port when running `server.js` directly. |
| `TRUST_PROXY` | `false` | Set to `true` when behind a reverse proxy so `X-Forwarded-For` is used for rate limiting. |
| `CAPTCHA_SECRET` | *(random)* | Optional HMAC secret for signing anti-bot challenge tokens. Generated automatically at startup if omitted. |

## API Endpoints

### `GET /api/challenge`

Issues a new anti-bot challenge containing a signed token and an inline SVG math image.

**Success Response (`200 OK`):**

```json
{
  "token": "<base64url-payload>.<hmac-signature>",
  "image": "data:image/svg+xml;base64,..."
}

```

### `GET /api/check`

Verifies the anti-bot challenge, fetches the target webpage server-side, and returns its raw HTML, HTTP status code, and final resolved URL.

**Query Parameters:**

* `url` (required): The website URL to inspect (e.g. `https://example.com`).
* `captchaToken` (required): Signed challenge token obtained from `/api/challenge`.
* `captchaAnswer` (required): Numeric solution to the SVG math challenge.
* `hp` (optional): Honeypot parameter; must be empty.

**Success Response (`200 OK`):**

```json
{
  "html": "<!doctype html>...",
  "status": 200,
  "finalUrl": "[https://example.com/](https://example.com/)"
}

```

### `GET /health`

Returns `{"status":"ok"}` with HTTP `200` when the server is running.

## Security Details

* **Anti-Bot & Replay Protection:** Challenges are rendered as randomised SVG graphics, expire after 5 minutes, require at least 1.2 seconds before submission, and invalidate their nonce upon successful verification.
* **SSRF & DNS Rebinding Protection:** Only `http:` and `https:` protocols are permitted. Hostnames are resolved via DNS before connecting, all loopback, private, link-local, CGNAT, NAT64, multicast, and reserved IPv4/IPv6 ranges are blocked, and the validated IP addresses are pinned directly to the outbound socket to prevent TOCTOU DNS rebinding.
* **Abuse & Resource Limits:** Upstream requests share a 10-second total deadline across at most 5 redirects, enforce a 2 MB decompressed response size cap, limit concurrent outbound checks, and apply per-IP sliding-window rate limits (30 checks/minute and 60 challenges/minute).
* **XSS Prevention:** Extracted attributes and link text are rendered exclusively via safe DOM APIs (`textContent`) rather than `innerHTML`, and non-HTTP(S) schemes are prevented from rendering as clickable anchors.
* **Container Hardening:** Runs as the unprivileged `node` user with a read-only root filesystem, `cap_drop: [ALL]`, and `no-new-privileges` enabled.
