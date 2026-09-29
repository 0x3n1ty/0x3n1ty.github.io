---
title: Schrödinger Package
date: 2026-09-30
tags:
  - web
  - python-package
  - pip
  - ctf-writeups
---

![chall](../writings/H7CTF-2026-Quals/Schrödinger-Package/1.png)

The description was short. A package registry. Upload a Python package, it gets inspected, then it gets run before being cleared. *Make the service hand you the flag.* My immediate assumption was SSRF. Something in the package metadata that points to an internal URL, and the server fetches it while inspecting. That assumption was wrong, and the path to the real answer only made sense after I stopped trying to make SSRF work.

When I opened the site, the UI was broken — no styling, no JavaScript, just unstyled HTML. The page was served over HTTPS but every `<script>` and `<link>` tag pointed at `http://` URLs, and browsers block mixed content, so the JS and CSS were silently dropped. I poked at it a bit in the DevTools console but eventually just went straight to the source.

The frontend code confirmed the flow I'd already guessed from the UI: upload a `.whl`, then trigger an inspection, then trigger a runtime job. The `package.js` file called `/api/packages/{id}/inspection` and `/api/packages/{id}/runtime`, and the runtime response was what contained the flag field.

In the network tab I noticed the `server: uvicorn` header. Uvicorn is the ASGI server that FastAPI runs on by default. FastAPI, unless you explicitly disable it, publishes a full OpenAPI schema at `/openapi.json` and a Swagger UI at `/docs`. Both were public. `GET /openapi.json` gave me every endpoint, every parameter, and every response schema without guessing a single thing. The schema for `RuntimeJobResponse` had a `flag: string | null` field, and its description read: *"Immediate Portal response; flag is transient and never persisted."* That one line told me the whole shape of the challenge. The flag is computed when you request a runtime job, returned in the response body, and stored nowhere retrievable. Whatever triggers it must be satisfied during that one request.

![api-docs](../writings/H7CTF-2026-Quals/Schrödinger-Package/2.png)

My first real exploit attempt was the SSRF I'd assumed at the start. Putting an internal URL into package metadata — `Home-page`, `Project-URL`, an RST `.. image::` directive in the description — is a real vulnerability class in package registries. PyPI's own backend had bugs like this. I built a wheel whose `__init__.py` used `urllib` to hit several likely internal targets and printed the results. Every single one came back with `<urlopen error [Errno 1] Operation not permitted>`.


![upload-run](../writings/H7CTF-2026-Quals/Schrödinger-Package/4.png)

![payload](..//writings/H7CTF-2026-Quals/Schrödinger-Package/3.png)


That error is `EPERM` from the kernel — not a firewall rejection, not a DNS failure. `EPERM` on `socket()` means the syscall itself is blocked by seccomp, a Linux kernel feature that lets a process install a BPF filter on syscalls. A firewall rejects traffic *after* the syscall succeeds. Seccomp rejects the syscall *before* the kernel even looks at the destination. DNS rebinding, alternate hostnames, IP tricks — all irrelevant. The syscall never executes. That was the moment my SSRF assumption died. There is no network from inside the imported package.

But if sockets are blocked, file reads clearly worked — the `EPERM` was only on `socket()`. I wrote a payload that opened every likely flag path from inside the import:

![file-read](../writings/H7CTF-2026-Quals/Schrödinger-Package/6.png)

![source-walk](../writings/H7CTF-2026-Quals/Schrödinger-Package/7.png)

The output was instructive. `/etc/passwd` was fully readable. `/flag`, `/flag.txt`, `/app/flag.txt`, `/root/flag.txt`, `/tmp/flag.txt`, `/proc/1/environ` — all either `FileNotFoundError` or `PermissionError`. The `PermissionError` on `/root/flag.txt` and `/proc/1/environ` is a Unix permission error, not a seccomp denial, which proves the `open()` syscall itself is allowed. The files just aren't readable by our UID (10001). And there's no flag sitting at any guessable path, because the flag isn't in this container at all. But we *could* read the server's source.

So I wrote a payload that walks the filesystem from inside the import and dumps anything interesting. It had to be fast — the smoke import has a 12-second timeout — so it walked only likely roots, capped depth, capped file size, and filtered by extension and filename keywords. The output showed UID 10001, user `schrodinger`, and a filesystem where `/app` contains the application source.

![portal-api](../writings/H7CTF-2026-Quals/Schrödinger-Package/8.png)

The tree under `/app/schrodinger/` was the whole app: `config.py`, `main.py`, `models.py`, `store.py`, plus three subpackages — `runtime/`, `inspector/`, and `portal/`. Reading `runtime/limits.py` showed exactly how the sandbox was built. The runtime entrypoint calls `prctl(PR_SET_DUMPABLE, 0)` first (that's why `/proc/1/environ` was denied), then installs a **seccomp blacklist** on the child before `execve`. The blacklist denies only specific syscalls — `socket`, `socketpair`, `kill`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `pidfd_send_signal`, `kcmp`, `perf_event_open`, `io_uring_setup`, and a handful of signal-related ones. Everything else is allowed: `open`, `read`, `write`, `execve`, `fork`, `clone`, `dup`, `pipe`. The author blocked the two modern ways to steal a parent's file descriptor (`pidfd_getfd` and `process_vm_readv`), and blocked network creation. But they deliberately left file reads open, because file reads aren't the threat model.


![flag](../writings/H7CTF-2026-Quals/Schrödinger-Package/9.png)


Then I dumped `portal/api.py`. That file has every route and the flag logic. It reads the flag from `FLAG` or `/app/flag.txt` — on the portal, not in our container — and only returns it when a nine-condition boolean called `releases_flag` evaluates to `True`. Most of the conditions are bookkeeping: the job completed, the import succeeded, the module path is what we expect, the hashes are valid hex-64. Two of them are the entire challenge. `result.archive_occurrences > 1` requires the wheel to contain **more than one entry at the module path**. And `inspector_module.sha256 != result.installed_sha256` requires the inspector's hash of that file to differ from the hash of the file that pip actually installed. In plain English: the archive must contain the module twice, and the two copies must have different content.

That's a parser differential in the ZIP format. A wheel is a ZIP file, and the ZIP format permits duplicate entry names. Python's `zipfile` module will write such an archive happily — it prints a `UserWarning: Duplicate name` which you silence. Different components read the archive differently. The **inspector** builds a manifest by iterating the archive's info list and looking up the module path with `next(...)`, which returns the **first** matching entry. **pip**, extracting in order, writes both entries to the same disk path — the **last** write wins. The **runtime** reads the installed file from disk, so its `installed_sha256` is the hash of the **second** entry. Inspector and runtime disagree, and the flag condition is designed to detect exactly that disagreement.

The final wheel was trivial. The script writes two entries at `evil/__init__.py`. The first is `print('decoy A loaded')` — what the inspector sees. The second is `print('PAYLOAD_B loaded')` — what pip installs. Same standard `.dist-info` files. Same `RECORD`. When `zipfile` printed the duplicate-name warning, we ignored it. The archive was valid, both entries preserved in order.

Upload, inspect, run. The response body contained the flag directly:

```python
#!/usr/bin/env python3
import io
import os
import json
import time
import zipfile
import urllib.request
import urllib.error

BASE = "https://web-e47a970cb7914565.web.h7tex.com"

NAME = "evil"
VERSION = "1.0"


def build_wheel():
    """Build a wheel with TWO entries at the module path.

    The inspector records the first one's SHA-256, pip installs the
    second one. That divergence satisfies the portal's release check.
    """
    dist = f"{NAME}-{VERSION}"
    di = f"{dist}.dist-info"
    module_path = f"{NAME}/__init__.py"

    decoy = "print('decoy A loaded', flush=True)\n"
    payload = "print('PAYLOAD_B loaded', flush=True)\n"

    files = {
        f"{di}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {NAME}\n"
            f"Version: {VERSION}\n"
            "Summary: x\n"
            "License: MIT\n"
        ),
        f"{di}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: manual\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
        f"{di}/top_level.txt": NAME + "\n",
        f"{di}/RECORD": "",
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, content in files.items():
            z.writestr(path, content)
        # The trick: same path, two entries, different content.
        z.writestr(module_path, decoy)
        z.writestr(module_path, payload)

    return f"{NAME}-{VERSION}-py3-none-any.whl", buf.getvalue()


def req(method, path, data=None, headers=None):
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header("Accept", "*/*")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            body = resp.read()
            ct = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} {method} {path}: {e.read()[:400]!r}")
    return json.loads(body) if "json" in ct else body.decode()


fn, blob = build_wheel()

# Upload the wheel
b = "----x" + os.urandom(6).hex()
body = (
    f"--{b}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="{fn}"\r\n'
    f"Content-Type: application/octet-stream\r\n\r\n"
).encode() + blob + f"\r\n--{b}--\r\n".encode()

up = req("POST", "/api/packages", body,
         {"Content-Type": f"multipart/form-data; boundary={b}"})
aid = up["artifact_id"]
print("[*] artifact_id =", aid)

# Inspection must run first, otherwise the runtime job fails with
# "package has no inspection record"
req("POST", f"/api/packages/{aid}/inspection", b"")
time.sleep(0.5)

# Trigger the runtime job and read the flag from the response
job = req("POST", "/api/runtime/jobs",
          json.dumps({"artifact_id": aid}).encode(),
          {"Content-Type": "application/json"})

print("[*] status =", job.get("status"), "duration_ms =", job.get("duration_ms"))
for line in job.get("output", []):
    print("    " + line)

print()
print("[*] flag =", job.get("flag"))
```

![flag](../writings/H7CTF-2026-Quals/Schrödinger-Package/10.png)

```
[cva@archvm create_a_wheel]$ cat job-5d12a0f2541e4852981c7e4b6c81c400.log 
status=completed duration_ms=3692
Submitted artifact SHA-256 verified.
Installed module path: evil/__init__.py
Installed module SHA-256: 757f2b75c394d6ea04ad010a66136597f955acbd5c8abf5ddc6e708b5945b3b8
Processing ./evil-1.0-py3-none-any.whl
Installing collected packages: evil
Successfully installed evil-1.0

SMOKE_PID:77
PAYLOAD_B loaded
Imported evil
```

The job output showed `PAYLOAD_B loaded`, confirming pip had installed the second copy while the inspector had recorded the first. That disagreement is the whole vulnerability. The service is trusting two different parsers to agree about the contents of the same archive, and there is a way to make them disagree — by duplicating a ZIP entry. No network, no install-time code execution, no sandbox escape. Just a wheel with two copies of the same file, and two components of the system that disagree about which one is real.
