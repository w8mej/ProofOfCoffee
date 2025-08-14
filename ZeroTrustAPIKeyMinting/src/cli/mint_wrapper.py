"""
cli/mint_webauthn_loopback.py — Developer-friendly CLI that performs WebAuthn in a local browser,
captures the assertion, forwards it to the backend `/mint`, and prints a one-click curl example.

Security & Ops
- Purpose: Provide a **zero-friction** developer flow to obtain short-lived, scoped JWTs by
  proving hardware possession (WebAuthn). The CLI spins up a loopback HTTP server only on localhost
  and opens the default browser to complete the WebAuthn assertion.
- Trust boundaries:
  • Loopback server (127.0.0.1) receives the WebAuthn assertion and never exposes it externally.
  • The actual verification happens server-side at `/webauthn/assert/start` and `/mint`.
- CSRF/CSWSH protection: This PoC intentionally avoids cross-origin fetches by serving the small
  page from the loopback origin. In production, prefer a single trusted origin (the backend) and
  consider PKCE-style nonces/state values in the local page exchange.
- Data handling:
  • No long-term secrets are stored; the JWT printed is short-lived by design.
  • Avoid logging the assertion contents beyond what is necessary.

Tunable / Config
- COORDINATOR_URL: Base URL of the mint backend (default: http://127.0.0.1:8080).
- PORT: Loopback port to serve the helper page (default 8765; change below if needed).
- CLI flags:
  --user     : username/email subject to mint for
  --role     : logical role used by policy (engineer/sre/…)
  --scopes   : comma-separated scopes (e.g., "read:logs,write:staging")
  --ttl      : token TTL in seconds (policy-capped server-side)

Operational Guidance
- This tool is intended for **developer laptops**. Do not expose the loopback server externally.
- Network policies and firewalls should prevent external access to 127.0.0.1 ports from remote hosts.
- Ensure the backend validates origin/RP ID and the assertion against stored credentials, rate limits,
  and audits the mint event.

Production Considerations / Improvements
- Replace the loopback flow with a **device-code** or **native app** flow that opens the system browser
  to your real origin and uses a back-channel to deliver the assertion (e.g., via OAuth device code
  or WebSockets with CSRF tokens).
- Add **nonce/state** binding between `/assert/start` and `/done` to prevent local page injection.
- Integrate with the CLI’s secure keyring to store last used username and preferred scopes (opt-in).
- Print a condensed, copy-paste friendly `curl` using an environment variable (e.g., `AUTH=$(mint …)`).
"""

import base64
import http.server
import json
import os
import socketserver
import threading
import webbrowser
from urllib.parse import parse_qs, urlparse

import click
import requests

# Minimal HTML UI served on loopback. It:
# 1) POSTs to the local /assert/start, which proxies to backend /webauthn/assert/start.
# 2) Runs navigator.credentials.get() with the returned challenge/allowCredentials.
# 3) POSTs the resulting assertion back to local /done, where the CLI picks it up and
#    immediately forwards to backend /mint.
HTML = r"""<!doctype html>
<html><meta charset="utf-8"><title>Mint via WebAuthn</title>
<body style="font-family:system-ui;margin:2rem">
<h1>Mint via WebAuthn</h1>
<label>Username</label><input id="u" value="alice@example.com"><br><br>
<button onclick="run()">Assert & Send</button>
<pre id="log"></pre>
<script>
const b64u = {
  enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),
  dec: s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0))
};
async function run(){
  const username = document.getElementById('u').value;
  // Request a fresh challenge and allowCredentials from the backend (proxied by loopback server).
  const s1 = await fetch('/assert/start', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({username})
  }).then(r=>r.json());

  // Perform WebAuthn assertion in the browser; rpId must match backend policy.
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: b64u.dec(s1.challenge),
      rpId: s1.rpId,
      allowCredentials: (s1.allowCredentials || []).map(c => ({type:'public-key', id: b64u.dec(c.id)}))
    }
  });

  // Prepare payload for server-side verification (assertion_response fields).
  const payload = {
    rawId: b64u.enc(cred.rawId),
    authenticatorData: b64u.enc(cred.response.authenticatorData),
    clientDataJSON: b64u.enc(cred.response.clientDataJSON),
    signature: b64u.enc(cred.response.signature),
    username
  };

  // Send assertion back to the loopback server; the CLI will forward to /mint.
  await fetch('/done', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload)});
  document.getElementById('log').textContent = 'Assertion sent. You can close this window.';
}
</script>
</body></html>"""


class Handler(http.server.SimpleHTTPRequestHandler):
    """
    Loopback HTTP handler:
      GET /            → serves the helper HTML
      POST /assert/start → proxies to backend /webauthn/assert/start
      POST /done       → captures assertion JSON into the server object
    """
    # Silence noisy default logging (optional). Uncomment to reduce console output.
    # def log_message(self, format, *args): pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML.encode("utf-8"))
            return
        # Fall back to base class for static files (unused here).
        return super().do_GET()

    def do_POST(self):
        # Read request body
        length = int(self.headers.get("content-length", 0))
        data = self.rfile.read(length)

        if self.path == "/assert/start":
            # Proxy the request to backend (no secrets here; only username)
            upstream = os.environ.get(
                "COORDINATOR_URL", "http://127.0.0.1:8080")
            try:
                r = requests.post(
                    upstream + "/webauthn/assert/start",
                    data=data,
                    headers={"content-type": "application/json"},
                    timeout=10,
                )
                self.send_response(r.status_code)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(r.content)
            except Exception as e:
                self.send_response(502)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"error": "upstream", "detail": str(e)}).encode("utf-8"))
            return

        if self.path == "/done":
            # Capture the assertion and signal the main thread
            try:
                self.server.assertion = json.loads(data.decode("utf-8"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"bad assertion")
            return

        # Unknown route
        self.send_response(404)
        self.end_headers()


@click.command()
@click.option("--user", required=True, help="username/email")
@click.option("--role", default="engineer", show_default=True)
@click.option("--scopes", default="read:logs,write:staging", show_default=True, help="comma-separated scopes")
@click.option("--ttl", type=int, default=900, show_default=True, help="token TTL seconds (policy-capped)")
def mint(user: str, role: str, scopes: str, ttl: int) -> None:
    """
    Entry point for the CLI. Spawns the loopback server, opens the browser to perform
    WebAuthn, forwards the assertion to `/mint`, and prints a curl example.

    Flow:
      1) Start a loopback HTTP server on PORT.
      2) Open default browser to http://127.0.0.1:PORT/.
      3) The page POSTs username → /assert/start (proxied to backend).
      4) Browser performs navigator.credentials.get(), POSTs assertion → /done.
      5) CLI reads captured assertion and POSTs to backend /mint.
      6) Prints returned JWT and a one-click curl example.
    """
    PORT = 8765  # Tunable: change if port is occupied

    # Start a basic HTTP server (single-threaded handle_request loop)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.assertion = None

        # Open default browser automatically
        threading.Thread(
            target=lambda: webbrowser.open(f"http://127.0.0.1:{PORT}/"),
            daemon=True,
        ).start()

        click.echo("Complete WebAuthn in your browser...")

        # Serve requests until /done posts the assertion
        while httpd.assertion is None:
            httpd.handle_request()

        upstream = os.environ.get("COORDINATOR_URL", "http://127.0.0.1:8080")

        # Prepare mint request body. The server performs full verification and policy checks.
        body = {
            "user": user,
            "role": role,
            "scopes": [s.strip() for s in scopes.split(",") if s.strip()],
            "ttl_seconds": ttl,
            "auth_method": "webauthn",
            "webauthn_assertion": httpd.assertion,
        }

        try:
            r = requests.post(upstream + "/mint", json=body, timeout=15)
        except Exception as e:
            click.secho(f"Error calling /mint: {e}", fg="red")
            return

        # Print raw response for transparency
        click.echo(r.text)

        # If JSON payload contains a token, offer a one-click curl example
        try:
            out = r.json()
            token = out.get("token", "")
            if token:
                click.echo("\nOne-click curl example (replace URL):")
                click.echo(
                    f"curl -H 'Authorization: Bearer {token}' https://service.example.internal/health")
        except Exception:
            # Non-JSON response; ignore
            pass


if __name__ == "__main__":
    mint()
