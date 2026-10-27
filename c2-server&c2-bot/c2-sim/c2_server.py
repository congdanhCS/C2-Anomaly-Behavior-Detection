#!/usr/bin/env python3
"""
c2_server.py - Server C2 GIA LAP cho lab KLTN (chay tren VM c2-server).

An toan theo thiet ke:
  - chi bind vao dia chi IP private/loopback (mang lab Host-only)
  - chi tra loi noi dung co dinh, vo hai
  - KHONG thuc thi lenh, KHONG doc/ghi file theo yeu cau cua client

Dich vu: http (8080), https (8443, can --cert/--key), tcp (4444), udp (9999), dns (53)

Vi du:
  sudo python3 c2_server.py --bind 192.168.10.13
  sudo python3 c2_server.py --bind 192.168.10.13 --services http,https,tcp,udp,dns \
       --cert ~/Desktop/c2-sim/c2.crt --key ~/Desktop/c2-sim/c2.key
"""
import argparse
import ipaddress
import random
import socket
import ssl
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_REPLY = b'{"task":"none","sleep":30}'
VERBOSE = False


# ---------------------------------------------------------------- HTTP/HTTPS
class Handler(BaseHTTPRequestHandler):
    server_version = "LabC2/1.0"
    protocol_version = "HTTP/1.1"

    def _reply(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(min(length, 1_000_000))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(HTTP_REPLY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(HTTP_REPLY)
        self.close_connection = True

    do_GET = _reply
    do_POST = _reply

    def log_message(self, fmt, *args):
        if VERBOSE:
            sys.stderr.write("[http] %s %s\n" % (self.client_address[0], fmt % args))


def serve_http(host, port, ctx=None):
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    if ctx is not None:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[+] {'https' if ctx else 'http'} lang nghe {host}:{port}", flush=True)
    httpd.serve_forever()


# ---------------------------------------------------------------------- TCP
def _tcp_client(conn):
    with conn:
        conn.settimeout(5)
        try:
            while conn.recv(65536):  # doc den khi client dong chieu gui (FIN)
                pass
            conn.sendall(b"ACK\n")
        except OSError:
            pass


def serve_tcp(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(32)
    print(f"[+] tcp lang nghe {host}:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_tcp_client, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------------- UDP
def serve_udp(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((host, port))
    print(f"[+] udp lang nghe {host}:{port}", flush=True)
    while True:
        _, addr = srv.recvfrom(65535)
        srv.sendto(b"ACK", addr)


# ---------------------------------------------------------------------- DNS
def build_dns_reply(data, nx_ratio):
    """Tra loi truy van DNS: NXDOMAIN voi xac suat nx_ratio, nguoc lai 1 ban ghi A co dinh."""
    if len(data) < 17:
        return None
    i = 12
    while i < len(data) and data[i] != 0:
        i += data[i] + 1
    end = i + 1  # byte ngay sau ky tu ket thuc qname
    question = data[12:end + 4]
    if len(question) != (end - 12) + 4:
        return None
    if random.random() < nx_ratio:
        flags, an, answer = 0x8183, 0, b""
    else:
        flags, an = 0x8180, 1
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([10, 20, 30, 40])
    return data[:2] + struct.pack("!HHHHH", flags, 1, an, 0, 0) + question + answer


def serve_dns(host, port, nx_ratio):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((host, port))
    print(f"[+] dns lang nghe {host}:{port} (nx_ratio={nx_ratio})", flush=True)
    while True:
        data, addr = srv.recvfrom(4096)
        reply = build_dns_reply(data, nx_ratio)
        if reply:
            srv.sendto(reply, addr)


# --------------------------------------------------------------------- main
def run(name, fn, *a):
    try:
        fn(*a)
    except Exception as e:  # in loi ro rang (vi du port 53 can sudo)
        print(f"[LOI] dich vu {name}: {e}", file=sys.stderr, flush=True)


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description="C2 server gia lap (chi dung trong lab co lap)")
    ap.add_argument("--bind", required=True, help="IP private cua VM nay, vd 192.168.10.13")
    ap.add_argument("--services", default="http,tcp,udp,dns",
                    help="danh sach, cach nhau dau phay: http,https,tcp,udp,dns")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--https-port", type=int, default=8443)
    ap.add_argument("--tcp-port", type=int, default=4444)
    ap.add_argument("--udp-port", type=int, default=9999)
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--nx-ratio", type=float, default=0.0, help="ty le tra NXDOMAIN (0..1)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    ip = ipaddress.ip_address(args.bind)
    if ip.is_unspecified or not (ip.is_private or ip.is_loopback):
        sys.exit("Tu choi: --bind phai la IP private cu the (khong dung 0.0.0.0 hay IP public).")

    services = {s.strip() for s in args.services.split(",") if s.strip()}
    threads = []
    if "http" in services:
        threads.append(("http", serve_http, (args.bind, args.http_port)))
    if "https" in services:
        if not (args.cert and args.key):
            sys.exit("Dich vu https can --cert va --key")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        threads.append(("https", serve_http, (args.bind, args.https_port, ctx)))
    if "tcp" in services:
        threads.append(("tcp", serve_tcp, (args.bind, args.tcp_port)))
    if "udp" in services:
        threads.append(("udp", serve_udp, (args.bind, args.udp_port)))
    if "dns" in services:
        threads.append(("dns", serve_dns, (args.bind, args.dns_port, args.nx_ratio)))
    if not threads:
        sys.exit("Khong co dich vu nao duoc chon")

    for name, fn, a in threads:
        threading.Thread(target=run, args=(name, fn) + a, daemon=True).start()
    print("Server dang chay. Nhan Ctrl+C de dung.", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nDa dung.")


if __name__ == "__main__":
    main()
