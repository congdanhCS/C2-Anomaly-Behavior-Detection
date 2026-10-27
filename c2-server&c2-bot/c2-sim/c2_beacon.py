#!/usr/bin/env python3
"""
c2_beacon.py - Bo mo phong HANH VI beaconing cho lab KLTN (chay tren VM c2-bot).

Day KHONG phai malware: chi gui request dinh ky den c2_server.py trong mang lab,
khong nhan/thuc thi lenh, khong ton tai lau dai, khong lay du lieu may.
Chi chap nhan dich den la IP private.

Che do (--mode):
  http   POST/GET dinh ky toi cong 8080
  https  HTTPS (TLS tu ky) toi cong 8443, co SNI
  dns    truy van DNS UDP dinh ky toi cong 53 (--dns-style random: label entropy cao)
  tcp    ket noi TCP dinh ky toi cong 4444, gui --payload byte
  udp    datagram UDP dinh ky toi cong 9999

Thoi gian cho giua 2 beacon = interval * (1 + uniform(-jitter, +jitter)).

Vi du:
  python3 c2_beacon.py --mode http --server 192.168.10.13 --scenario c2_http_01 \
          --interval 30 --jitter 0.1 --payload 200 --duration 1800
"""
import argparse
import csv
import datetime
import http.client
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import sys
import time

DEFAULT_PORT = {"http": 8080, "https": 8443, "dns": 53, "tcp": 4444, "udp": 9999}
BOT_ID = "bot-%04x" % random.randint(0, 0xFFFF)


class SNIHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS toi IP nhung van gui SNI (server_name) de Zeek ghi vao ssl.log."""

    def __init__(self, *a, sni=None, **kw):
        super().__init__(*a, **kw)
        self._sni = sni

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._sni or self.host)


def beacon_http(args, port, tls):
    body = os.urandom(args.payload) if args.payload > 0 else None
    headers = {"User-Agent": args.user_agent, "X-Bot-Id": BOT_ID, "Connection": "close"}
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # server tu ky trong lab
        conn = SNIHTTPSConnection(args.server, port, timeout=8, context=ctx, sni=args.sni)
    else:
        conn = http.client.HTTPConnection(args.server, port, timeout=8)
    try:
        if body is None:
            conn.request("GET", f"/api/v1/checkin?id={BOT_ID}", headers=headers)
            sent = 0
        else:
            headers["Content-Type"] = "application/octet-stream"
            conn.request("POST", "/api/v1/checkin", body=body, headers=headers)
            sent = len(body)
        resp = conn.getresponse()
        resp.read()
        return sent, f"status={resp.status}"
    finally:
        conn.close()


def dns_packet(name):
    header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def beacon_dns(args, port):
    if args.dns_style == "random":
        n = max(8, min(args.payload if args.payload > 0 else 20, 60))
        label = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))
    else:
        label = "beacon"
    pkt = dns_packet(f"{label}.{args.domain}")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (args.server, port))
        data, _ = s.recvfrom(4096)
        rcode = data[3] & 0x0F
        return len(pkt), f"rcode={rcode}"
    finally:
        s.close()


def beacon_tcp(args, port):
    data = os.urandom(args.payload) if args.payload > 0 else b"BEACON\n"
    s = socket.create_connection((args.server, port), timeout=5)
    try:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        reply = s.recv(1024)
        return len(data), f"reply={len(reply)}B"
    finally:
        s.close()


def beacon_udp(args, port):
    data = os.urandom(args.payload) if args.payload > 0 else b"BEACON"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(data, (args.server, port))
        reply, _ = s.recvfrom(1024)
        return len(data), f"reply={len(reply)}B"
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="Mo phong beaconing (chi dung trong lab co lap)")
    ap.add_argument("--mode", required=True, choices=list(DEFAULT_PORT))
    ap.add_argument("--server", required=True, help="IP private cua c2-server")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--scenario", required=True, help="ten scenario, vd c2_http_01")
    ap.add_argument("--interval", type=float, default=30.0, help="giay giua 2 beacon")
    ap.add_argument("--jitter", type=float, default=0.1, help="0..1, vd 0.1 = +-10%%")
    ap.add_argument("--payload", type=int, default=0, help="so byte gui (dns: do dai label)")
    ap.add_argument("--duration", type=float, default=0, help="tong giay chay, 0 = den khi Ctrl+C")
    ap.add_argument("--count", type=int, default=0, help="so beacon toi da, 0 = khong gioi han")
    ap.add_argument("--seed", type=int, default=None, help="co dinh seed de tai lap")
    ap.add_argument("--user-agent", default="Mozilla/5.0 (X11; Linux x86_64) LabBeacon/1.0")
    ap.add_argument("--sni", default="c2lab.test")
    ap.add_argument("--domain", default="c2lab.test")
    ap.add_argument("--dns-style", choices=["fixed", "random"], default="fixed")
    ap.add_argument("--outdir", default=os.path.expanduser("~/Desktop/c2-sim/logs"))
    args = ap.parse_args()

    ip = ipaddress.ip_address(args.server)
    if not (ip.is_private or ip.is_loopback):
        sys.exit("Tu choi: chi cho phep dich la IP private trong lab.")
    if not 0 <= args.jitter <= 1:
        sys.exit("--jitter phai trong khoang 0..1")
    if args.seed is not None:
        random.seed(args.seed)

    port = args.port or DEFAULT_PORT[args.mode]
    os.makedirs(args.outdir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.outdir, f"{args.scenario}_{stamp}")
    started = time.time()

    params = {k: v for k, v in vars(args).items()}
    params.update({"port": port, "bot_id": BOT_ID, "start_epoch": started})
    with open(base + "_params.json", "w") as f:
        json.dump(params, f, indent=2)

    fh = open(base + "_beacons.csv", "w", newline="")
    log = csv.writer(fh)
    log.writerow(["ts_epoch", "ts_iso", "seq", "scenario", "mode", "server", "port",
                  "planned_sleep_s", "bytes_sent", "ok", "detail"])

    print(f"[+] {args.scenario}: mode={args.mode} -> {args.server}:{port} "
          f"interval={args.interval}s jitter={args.jitter} payload={args.payload}", flush=True)
    print(f"[+] log: {base}_beacons.csv   (Ctrl+C de dung)", flush=True)

    seq = 0
    next_at = time.monotonic()
    try:
        while True:
            now = time.time()
            if args.duration and now - started >= args.duration:
                break
            if args.count and seq >= args.count:
                break
            seq += 1
            ok, sent, detail = 1, 0, ""
            try:
                if args.mode in ("http", "https"):
                    sent, detail = beacon_http(args, port, args.mode == "https")
                elif args.mode == "dns":
                    sent, detail = beacon_dns(args, port)
                elif args.mode == "tcp":
                    sent, detail = beacon_tcp(args, port)
                else:
                    sent, detail = beacon_udp(args, port)
            except Exception as e:
                ok, detail = 0, f"{type(e).__name__}: {e}"
            delay = args.interval * (1 + random.uniform(-args.jitter, args.jitter))
            log.writerow([f"{now:.6f}", datetime.datetime.fromtimestamp(now).astimezone().isoformat(),
                          seq, args.scenario, args.mode, args.server, port,
                          f"{delay:.3f}", sent, ok, detail])
            fh.flush()
            print(f"  #{seq:04d} ok={ok} sent={sent}B {detail} next in {delay:.1f}s", flush=True)
            next_at += delay
            time.sleep(max(0.0, next_at - time.monotonic()))
    except KeyboardInterrupt:
        print("\n[!] Dung boi nguoi dung")
    finally:
        fh.close()

    ended = time.time()
    print(f"[+] Xong: {seq} beacon trong {ended - started:.0f}s")
    print("\nChay tren SENSOR sau khi stop_capture.sh de ghi tham so vao meta.json:")
    print("  cd /home/orca/Desktop/lab-scripts && python3 add_meta.py label=c2 "
          f"mode={args.mode} interval={args.interval} jitter={args.jitter} payload={args.payload} "
          f"server_port={port} c2_ip={args.server} bot_ip=<IP_cua_c2-bot> beacons={seq}")


if __name__ == "__main__":
    main()
