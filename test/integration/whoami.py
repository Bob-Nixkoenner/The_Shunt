"""Tiny HTTP server answering with the client's IP. Test helper only."""
import http.server
import socket
import sys
import threading


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]
        if ip.startswith("::ffff:"):  # IPv4 client on the dual-stack socket
            ip = ip[len("::ffff:"):]
        body = (ip + "\n").encode()
        if self.path == "/mss":  # the MSS this connection ended up with
            body = (str(self.connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class V6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if socket.has_ipv6 and __import__("os").path.isdir("/proc/sys/net/ipv6"):
    servers = [V6(("::", int(p)), H) for p in sys.argv[1:]]
else:
    servers = [http.server.ThreadingHTTPServer(("0.0.0.0", int(p)), H) for p in sys.argv[1:]]
for s in servers[1:]:
    threading.Thread(target=s.serve_forever, daemon=True).start()
servers[0].serve_forever()
