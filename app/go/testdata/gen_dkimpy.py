"""Writes the fixtures sealed by dkimpy, an independent ARC implementation.

Run from app/go with dkimpy 1.1.8 and authres 1.2.0 installed:
    python3 -I testdata/gen_dkimpy.py
The private keys are made on the first run and stay out of git; only the
public records in keys.txt are kept, which is all the tests read. A new run
makes new keys and so new fixtures.
"""
import base64
import os
import subprocess
import dkim

HOPS = [("hop1", b"a.example", b"s1", b"mx.a.example"), ("hop2", b"b.example", b"s2", b"mx.b.example")]


def pub(name):
    if not os.path.exists(f"testdata/{name}.key"):
        subprocess.run(["openssl", "genrsa", "-out", f"testdata/{name}.key", "2048"], capture_output=True, check=True)
    der = subprocess.run(["openssl", "rsa", "-in", f"testdata/{name}.key", "-pubout", "-outform", "DER"],
                         capture_output=True, check=True).stdout
    return b"v=DKIM1; k=rsa; p=" + base64.b64encode(der)


KEYS = {}
for name, dom, sel, _ in HOPS:
    KEYS[sel + b"._domainkey." + dom + b"."] = pub(name)


def dnsfunc(qname, timeout=5):
    return KEYS.get(qname if qname.endswith(b".") else qname + b".")


def hop(msg, name, dom, sel, srv):
    # A hop's MX states the chain it found in its Authentication-Results,
    # as rspamd does; dkimpy seals a second instance only after that.
    found = b""
    if b"ARC-Seal:" in msg:
        found = b"; arc=" + dkim.arc_verify(msg, dnsfunc=dnsfunc)[0]
    msg = b"Authentication-Results: " + srv + b"; spf=pass smtp.mailfrom=alice@example.org" + found + b"\r\n" + msg
    key = open(f"testdata/{name}.key", "rb").read()
    sig = dkim.arc_sign(msg, sel, dom, key, srv, timestamp=1794787200)
    return b"".join(sig) + msg


BASE = (b"From: Alice <alice@example.org>\r\nTo: list@a.example\r\nSubject: arc fixture\r\n"
        b"Date: Mon, 16 Nov 2026 12:00:00 +0000\r\nMessage-ID: <arc-1@example.org>\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nline one\r\nline  two \r\n\r\n\r\n")

one = hop(BASE, *HOPS[0])
two = hop(one, *HOPS[1])
# The body changed after the first seal: the second hop finds the chain
# broken and seals it cv=fail.
broken = hop(one.replace(b"line one", b"line ONE"), *HOPS[1])

for fname, msg in [("one-hop.eml", one), ("two-hops.eml", two), ("cv-fail.eml", broken)]:
    open(f"testdata/{fname}", "wb").write(msg)
    print(fname, dkim.arc_verify(msg, dnsfunc=dnsfunc)[0])
with open("testdata/keys.txt", "wb") as f:
    for k, v in sorted(KEYS.items()):
        f.write(k + b" " + v + b"\n")
