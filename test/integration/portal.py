import http.server, sys
mode_file = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        mode = open(mode_file).read().strip()
        if mode == "portal":
            self.send_response(302); self.send_header("Location", "http://login.portal.test/welcome"); self.end_headers()
        else:
            b = b"NetworkManager is online\n"
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer((sys.argv[1], 8090), H).serve_forever()
