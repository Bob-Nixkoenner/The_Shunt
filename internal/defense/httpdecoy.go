package defense

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// The HTTP decoy (feature cowrie, ports 80, 8080, 8000, 8888): a fake login
// page and three bait files that carry the lock credentials (bait.go). It
// speaks just enough HTTP/1.x for scanners, curl and headless browsers; it
// never serves anything real and never forwards anything.

const (
	httpMaxRequests = 8                // requests per connection
	httpMaxRead     = 64 << 10         // bytes read per connection, headers included
	httpMaxBody     = 4 << 10          // form body that is looked at
	httpStepTimeout = 10 * time.Second // per request
)

func isHTTPPort(p int) bool { return p == 80 || p == 8080 || p == 8000 || p == 8888 }

// baitFiles are the paths that hand out the lock credentials.
var baitFiles = map[string]string{
	"/.env":           "env",
	"/.git/config":    "git",
	"/config.php.bak": "php",
}

// loginPaths show the fake login page (GET) and take the form (POST).
var loginPaths = map[string]bool{
	"/": true, "/index.html": true, "/login": true, "/login.php": true, "/admin": true, "/admin/login": true, "/signin": true,
}

func baitBody(kind string, b BaitCreds) (ctype, body string) {
	switch kind {
	case "env":
		return "text/plain", "APP_ENV=production\nAPP_DEBUG=false\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=app\n" +
			"DB_USERNAME=" + b.User + "\nDB_PASSWORD=" + b.Password + "\nAPI_KEY=" + b.Token + "\n"
	case "git":
		return "text/plain", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n" +
			"[remote \"origin\"]\n\turl = https://" + b.User + ":" + b.Password + "@git.internal/web/app.git\n" +
			"\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
	}
	return "application/octet-stream", "<?php\n// database settings\n$db_host = 'localhost';\n$db_user = '" + b.User + "';\n$db_pass = '" +
		b.Password + "';\n$db_name = 'app';\n$api_token = '" + b.Token + "';\n"
}

func loginPage(failed bool) string {
	msg := ""
	if failed {
		msg = `<p class="err">Invalid username or password.</p>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sign in</title></head><body>` +
		`<h1>Administration</h1>` + msg + `<form method="post" action="/login">` +
		`<label>Username <input name="username" autocomplete="username"></label>` +
		`<label>Password <input name="password" type="password" autocomplete="current-password"></label>` +
		`<button type="submit">Sign in</button></form></body></html>`
}

// formCreds pulls user and password out of a login body (form or JSON).
func formCreds(ctype string, body []byte) (user, pw string, ok bool) {
	pick := func(get func(string) string) {
		for _, k := range []string{"username", "user", "login", "email", "name"} {
			if v := get(k); v != "" {
				user = v
				break
			}
		}
		for _, k := range []string{"password", "pass", "passwd", "pwd"} {
			if v := get(k); v != "" {
				pw, ok = v, true
				break
			}
		}
	}
	if strings.Contains(strings.ToLower(ctype), "json") {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			pick(func(k string) string { s, _ := m[k].(string); return s })
		}
		return
	}
	if q, err := url.ParseQuery(string(body)); err == nil {
		pick(q.Get)
	}
	return
}

// httpTrap answers up to httpMaxRequests requests on one connection.
func (d *Decoys) httpTrap(c net.Conn, src netip.Addr, port int) {
	br := bufio.NewReader(&io.LimitedReader{R: c, N: httpMaxRead})
	for i := 0; i < httpMaxRequests; i++ {
		_ = c.SetDeadline(time.Now().Add(httpStepTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		status, ctype, body, done := d.httpServe(req, src, port)
		closing := done || req.Close || i == httpMaxRequests-1
		conn := "keep-alive"
		if closing {
			conn = "close"
		}
		head := fmt.Sprintf("HTTP/1.1 %d %s\r\nServer: nginx\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n",
			status, http.StatusText(status), ctype, len(body), conn)
		if req.Method == http.MethodHead {
			body = ""
		}
		if _, err := io.WriteString(c, head+body); err != nil || closing {
			return
		}
	}
}

// httpServe reports one request and builds the answer. done is true when the
// body was not read to its end (the connection cannot go on).
func (d *Decoys) httpServe(req *http.Request, src netip.Addr, port int) (status int, ctype, body string, done bool) {
	p := path.Clean("/" + req.URL.Path)
	method := cleanName(req.Method)
	extra := toolDetail(toolFromRequest(req.RequestURI, req.UserAgent()))

	// credentials in the header count like a form login
	if u, pw, ok := req.BasicAuth(); ok {
		d.login(src, port, "http", u, pw, extra)
		return http.StatusUnauthorized, "text/html", loginPage(true), false
	}
	if a := req.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		d.login(src, port, "http", "bearer", strings.TrimSpace(a[7:]), extra)
		return http.StatusUnauthorized, "application/json", `{"error":"invalid token"}`, false
	}

	if req.Method == http.MethodPost && loginPaths[p] {
		raw, _ := io.ReadAll(io.LimitReader(req.Body, httpMaxBody+1))
		done = len(raw) > httpMaxBody
		if user, pw, ok := formCreds(req.Header.Get("Content-Type"), raw[:min(len(raw), httpMaxBody)]); ok {
			d.login(src, port, "http", user, pw, extra)
		} else {
			d.hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevLow, Detail: "http " + method + " path=" + cleanName(p) + extra})
		}
		return http.StatusOK, "text/html", loginPage(true), done
	}
	if kind, isBait := baitFiles[p]; isBait {
		if b, ok := d.bait(); ok {
			d.hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevMedium, Detail: "http " + method + " path=" + p + " bait=served" + extra})
			ctype, body = baitBody(kind, b)
			return http.StatusOK, ctype, body, false
		}
	}
	d.hit(Hit{Src: src, Port: port, Kind: KindCowrie, Sev: SevLow, Detail: "http " + method + " path=" + cleanName(p) + extra})
	if loginPaths[p] {
		return http.StatusOK, "text/html", loginPage(false), false
	}
	return http.StatusNotFound, "text/html", "<html><body><h1>404 Not Found</h1></body></html>", false
}
