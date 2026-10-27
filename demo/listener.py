"""Demo 'attacker server' on 127.0.0.1:8099. Shows what the villain package would have stolen
if it had been installed without Gatekeeper. Local only; prints and discards the data."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            data = json.loads(body)
        except ValueError:
            data = {"raw": body.decode(errors="replace")}
        print("\n\033[41m STOLEN \033[0m data received from an npm install:")
        print(json.dumps(data, indent=2))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("demo listener on http://127.0.0.1:8099 (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8099), Handler).serve_forever()
