#!/usr/bin/env python3
import random
import socket
import time
import urllib.request

HTTP_TARGETS = [
    "http://example.com", "http://info.cern.ch", "http://neverssl.com",
    "http://httpbin.org/get",
    "https://www.wikipedia.org", "https://github.com", "https://www.python.org",
    "https://www.mozilla.org", "https://archive.org",
]
DNS_TARGETS = [
    "wikipedia.org", "python.org", "github.com", "ubuntu.com",
    "cloudflare.com", "mozilla.org", "archive.org", "youtube.com"
]

def do_http():
    url = random.choice(HTTP_TARGETS)
    try:
        urllib.request.urlopen(url, timeout=5)
        print(f"[HTTP] GET {url} OK", flush=True)
    except Exception as e:
        print(f"[HTTP] GET {url} FAIL: {e}", flush=True)

def do_dns():
    host = random.choice(DNS_TARGETS)
    try:
        socket.gethostbyname(host)
        print(f"[DNS] resolve {host} OK", flush=True)
    except Exception as e:
        print(f"[DNS] resolve {host} FAIL: {e}", flush=True)

if __name__ == "__main__":
    while True:
        if random.random() < 0.6:
            do_http()
        else:
            do_dns()
        time.sleep(random.uniform(3, 20)) #tg nghi phi chu ky khac C2 beaconing
