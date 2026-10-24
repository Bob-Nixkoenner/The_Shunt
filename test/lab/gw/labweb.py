"""Lab web server on the gateway, port 80.

Logs every request (canary names resolve to the gateway, so a request that
lands here took the untrusted network). In captive mode it acts as a portal:
connectivity checks get a redirect instead of the expected answer.

    python3 labweb.py <mode file> <log file>
"""
import http.server
import socket
import sys
import time

MODE_FILE, LOG_FILE = sys.argv[1], sys.argv[2]


class H(http.server.BaseHTTPRequestHandler):
    def handle_any(self):
        host = self.headers.get("Host", "")
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.time():.3f} {self.client_address[0]} {self.command} {host} {self.path}\n")
        mode = open(MODE_FILE).read().strip()
        if mode == "captive" and not host.startswith("login."):
            self.send_response(302)
            self.send_header("Location", "http://login.shuntlab.test/")
            self.end_headers()
            return
        body = b"shuntlab gateway\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = handle_any

    def log_message(self, *a):
        pass


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6  # dual stack: v4 clients come in as ::ffff:a.b.c.d


Server(("::", 80), H).serve_forever()
