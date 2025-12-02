---
title: Web Cache Deception - Complete Guide
date: 2025-11-29
category: guides
tags:
  - web
  - wcd
---

## Table of Contents
1. [Introduction](#introduction)
2. [Path Mapping Discrepancies](#path-mapping)
3. [Delimiter Discrepancies](#delimiters)
4. [Delimiter Decoding Discrepancies](#delimiter-decoding)
5. [Static Directory Cache Rules](#static-directory)
6. [Normalization Discrepancies](#normalization)
7. [File Name Cache Rules](#file-name)
8. [Browser-Specific Considerations](#browser-specific)
9. [Single-Page Applications (SPAs)](#spas)
10. [REST APIs](#rest-apis)
11. [GraphQL APIs](#graphql-apis)
12. [gRPC APIs](#grpc-apis)
13. [Prevention Strategies](#prevention)

---

<a name="introduction"></a>
## Introduction

Web Cache Deception is an attack where an attacker tricks a cache into storing sensitive dynamic content under a static URL, allowing unauthorized access to that content.

### Basic Attack Flow
1. Attacker identifies a cacheable endpoint with sensitive data
2. Attacker crafts a URL that appears to request a static resource
3. The cache treats it as a static request and stores the response
4. The origin server ignores the static-looking part and returns sensitive data
5. The sensitive data gets cached under a static URL
6. Attacker can now access the sensitive data via the static URL

---

<a name="path-mapping"></a>
## Path Mapping Discrepancies

### Vulnerable Server Code (Express.js)
```javascript
const express = require('express');
const app = express();

// This endpoint ignores extra path segments
app.get('/profile/:id', (req, res) => {
    // This will match /profile/123, /profile/123/anything, etc.
    const userId = req.params.id;
    res.json({ userId, data: "Sensitive profile data" });
});

app.listen(3000);
```

### Exploitation Steps
1. Identify a sensitive endpoint (e.g., `/profile/123`)
2. Try adding a static extension: `/profile/123.js`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Manually add various extensions to sensitive paths: `.js`, `.css`, `.ico`, `.png`
2. Use Burp Suite to send requests and check for caching behavior
3. Verify if the response contains sensitive data

### Fix
```javascript
const express = require('express');
const app = express();

// Only match exact path
app.get('/profile/:id', (req, res) => {
    // Reject requests with additional path segments
    if (req.path !== `/profile/${req.params.id}`) {
        return res.status(404).send('Not found');
    }
    const userId = req.params.id;
    res.json({ userId, data: "Sensitive profile data" });
});

app.listen(3000);
```

---

<a name="delimiters"></a>
## Delimiter Discrepancies

### Vulnerable Server Code (Java Spring)
```java
@RestController
public class ProfileController {
    
    // Spring treats ; as a delimiter for matrix parameters
    @GetMapping("/profile")
    public String getProfile() {
        // Both /profile and /profile;anything.css will match this
        return "User profile data";
    }
}
```

### Exploitation Steps
1. Identify a sensitive endpoint (e.g., `/profile`)
2. Try adding a delimiter and static extension: `/profile;user.css`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various delimiters: `;`, `?`, `#`, `:`
2. Combine with static extensions: `.js`, `.css`, `.ico`
3. Check for caching behavior

### Fix
```java
@RestController
public class ProfileController {
    
    @GetMapping("/profile")
    public String getProfile(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Reject requests with delimiters
        if (path.contains(";")) {
            throw new IllegalArgumentException("Invalid path");
        }
        return "User profile data";
    }
}
```

---

<a name="delimiter-decoding"></a>
## Delimiter Decoding Discrepancies

### Vulnerable Server Code (Node.js)
```javascript
const express = require('express');
const app = express();

// This server decodes %3f to ? before processing
app.use((req, res, next) => {
    req.url = decodeURIComponent(req.url);
    next();
});

app.get('/account', (req, res) => {
    res.json({ data: "Sensitive account information" });
});

app.listen(3000);
```

### Exploitation Steps
1. Identify a sensitive endpoint (e.g., `/account`)
2. Try URL-encoding a delimiter and adding a static extension: `/account%3f.css`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test URL-encoded delimiters: `%3f` (?), `%2f` (/), `%3b` (;), `%23` (#)
2. Combine with static extensions: `.js`, `.css`, `.ico`
3. Check for caching behavior

### Fix
```javascript
const express = require('express');
const app = express();

// Proper validation before decoding
app.use((req, res, next) => {
    const originalUrl = req.url;
    const decodedUrl = decodeURIComponent(originalUrl);
    
    // Reject if encoded and decoded versions differ significantly
    if (originalUrl !== decodedUrl && !isValidUrl(decodedUrl)) {
        return res.status(400).send('Invalid URL');
    }
    
    req.url = decodedUrl;
    next();
});

function isValidUrl(url) {
    // Implement proper URL validation
    return !url.includes('?') && !url.includes('#');
}

app.get('/account', (req, res) => {
    res.json({ data: "Sensitive account information" });
});

app.listen(3000);
```

---

<a name="static-directory"></a>
## Static Directory Cache Rules

### Vulnerable Server Code (Nginx)
```nginx
server {
    listen 80;
    server_name example.com;
    
    # Cache all requests to /static/ directory
    location /static/ {
        expires 1d;
        add_header Cache-Control "public";
        try_files $uri $uri/ @backend;
    }
    
    location @backend {
        proxy_pass http://backend;
    }
}
```

### Exploitation Steps
1. Identify a sensitive endpoint (e.g., `/account`)
2. Try path traversal to a static directory: `/static/../account`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various static directories: `/static/`, `/assets/`, `/resources/`, `/public/`
2. Use path traversal: `../`, `../../`, etc.
3. Check for caching behavior

### Fix
```nginx
server {
    listen 80;
    server_name example.com;
    
    # Normalize path before processing
    location / {
        # Merge consecutive slashes
        merge_slashes on;
        
        # Reject path traversal attempts
        if ($uri ~* "\.\.") {
            return 400;
        }
        
        try_files $uri $uri/ @backend;
    }
    
    location @backend {
        proxy_pass http://backend;
    }
}
```

---

<a name="normalization"></a>
## Normalization Discrepancies

### Vulnerable Server Code (Apache with mod_rewrite)
```apache
# Apache configuration
# Enable URL decoding and path normalization
RewriteEngine On

# Decode %2f to / and resolve dot-segments
RewriteCond %{REQUEST_URI} ^(.*)%2f(.*)$
RewriteRule ^ /%1/%2 [L,NE]

# Resolve dot-segments
RewriteCond %{REQUEST_URI} ^(.*)/\.\./(.*)$
RewriteRule ^ /%1/%2 [L,NE]
```

### Exploitation Steps
1. Identify a sensitive endpoint (e.g., `/profile`)
2. Try encoded path traversal to a static directory: `/static/..%2fprofile`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test encoded path traversal: `..%2f`, `..%2F`, `%2e%2e%2f`
2. Combine with static directories: `/static/`, `/assets/`, etc.
3. Check for caching behavior

### Fix
```apache
# Apache configuration
# Reject requests with encoded slashes
RewriteEngine On
RewriteCond %{THE_REQUEST} %2f [NC]
RewriteRule ^ - [F]
```

---

<a name="file-name"></a>
## File Name Cache Rules

### Vulnerable Server Code (Nginx)
```nginx
server {
    listen 80;
    server_name example.com;
    
    # Cache specific files
    location = /robots.txt {
        expires 7d;
        add_header Cache-Control "public";
        try_files $uri @backend;
    }
    
    location @backend {
        proxy_pass http://backend;
    }
}
```

### Exploitation Steps
1. Identify a sensitive endpoint (e.g., `/account`)
2. Try appending a cached filename: `/account/robots.txt`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various cached filenames: `robots.txt`, `favicon.ico`, `index.html`
2. Check for caching behavior

### Fix
```nginx
server {
    listen 80;
    server_name example.com;
    
    # Only cache actual files, not paths ending with filenames
    location = /robots.txt {
        if (!-f $request_filename) {
            return 404;
        }
        expires 7d;
        add_header Cache-Control "public";
    }
    
    location @backend {
        proxy_pass http://backend;
    }
}
```

---

<a name="browser-specific"></a>
## Browser-Specific Considerations

### URL Normalization in Browsers

Before sending a request, browsers perform several normalization steps:

1. **Scheme and Host Case Normalization**: Converting scheme and host to lowercase
2. **Path Normalization**: Resolving dot-segments (`.` and `..`)
3. **Percent-Encoding Normalization**: Decoding unreserved characters
4. **Fragment Removal**: Removing the fragment part (# and everything after it)

### Exploitation Steps
1. Craft a URL that will be normalized differently by the browser and the server
2. For example, use encoded characters that the browser decodes but the server doesn't
3. Check if the response is cached

### Testing Methods
1. Test with different browsers (Chrome, Firefox, Safari, Edge)
2. Use browser developer tools to inspect the actual request being sent
3. Compare with what the server receives

### Fix
Implement consistent URL normalization on the server side to match browser behavior.

---

<a name="spas"></a>
## Single-Page Applications (SPAs)

### Vulnerable Server Code (Express.js)
```javascript
const express = require('express');
const path = require('path');
const app = express();

// Serve SPA for any path under /app/
app.get('/app/*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'build/index.html'));
});

app.listen(3000);
```

### Exploitation Steps
1. Identify a sensitive route in the SPA (e.g., `/app/profile`)
2. Try adding a static extension: `/app/profile.js`
3. If the server returns the SPA with sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various static extensions: `.js`, `.css`, `.ico`
2. Check for caching behavior
3. Verify if the response contains sensitive data

### Fix
```javascript
const express = require('express');
const path = require('path');
const app = express();

// Serve SPA for any path under /app/
app.get('/app/*', (req, res) => {
    // Set cache headers to prevent caching
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.resolve(__dirname, 'build/index.html'));
});

app.listen(3000);
```

---

<a name="rest-apis"></a>
## REST APIs

### Vulnerable Server Code (Express.js)
```javascript
const express = require('express');
const app = express();

// This endpoint ignores extra path segments
app.get('/api/users/:id', (req, res) => {
    // This will match /api/users/123, /api/users/123/anything, etc.
    const userId = req.params.id;
    res.json({ userId, data: "Sensitive user data" });
});

app.listen(3000);
```

### Exploitation Steps
1. Identify a sensitive API endpoint (e.g., `/api/users/123`)
2. Try adding a static extension: `/api/users/123.js`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various static extensions: `.js`, `.css`, `.ico`
2. Check for caching behavior
3. Verify if the response contains sensitive data

### Fix
```javascript
const express = require('express');
const app = express();

// Only match exact path
app.get('/api/users/:id', (req, res) => {
    // Reject requests with additional path segments
    if (req.path !== `/api/users/${req.params.id}`) {
        return res.status(404).send('Not found');
    }
    const userId = req.params.id;
    res.json({ userId, data: "Sensitive user data" });
});

app.listen(3000);
```

---

<a name="graphql-apis"></a>
## GraphQL APIs

### Vulnerable Server Code (Apollo Server)
```javascript
const { ApolloServer, gql } = require('apollo-server');

const typeDefs = gql`
  type User {
    id: ID!
    name: String!
    email: String!
  }
  
  type Query {
    user(id: ID!): User
  }
`;

const resolvers = {
  Query: {
    user: (parent, { id }, context, info) => {
      return getUserById(id);
    }
  }
};

const server = new ApolloServer({
  typeDefs,
  resolvers
});

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`);
});
```

### Exploitation Steps
1. Identify a sensitive GraphQL query (e.g., `user(id: "123")`)
2. Try adding a static extension to the endpoint: `/graphql.js`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various static extensions: `.js`, `.css`, `.ico`
2. Check for caching behavior
3. Verify if the response contains sensitive data

### Fix
```javascript
const { ApolloServer, gql } = require('apollo-server');

const typeDefs = gql`
  type User {
    id: ID!
    name: String!
    email: String!
  }
  
  type Query {
    user(id: ID!): User
  }
`;

const resolvers = {
  Query: {
    user: (parent, { id }, context, info) => {
      return getUserById(id);
    }
  }
};

const server = new ApolloServer({
  typeDefs,
  resolvers,
  plugins: [
    {
      requestDidStart() {
        return {
          didResolveOperation(requestContext) {
            // Check if operation is a query and if it should be cached
            const operation = requestContext.request.operationName;
            if (operation === 'GetUser') {
              // Set cache control headers to prevent caching
              requestContext.response.http.headers.set('cache-control', 'no-store');
            }
          }
        };
      }
    }
  ]
});

server.listen().then(({ url }) => {
  console.log(`Server ready at ${url}`);
});
```

---

<a name="grpc-apis"></a>
## gRPC APIs

### Vulnerable Server Code (Node.js gRPC)
```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const PROTO_PATH = './user.proto';
const packageDefinition = protoLoader.loadSync(PROTO_PATH);
const userProto = grpc.loadPackageDefinition(packageDefinition).user;

function getUser(call, callback) {
  const userId = call.request.id;
  // Return sensitive user data
  callback(null, { id: userId, name: "John Doe", email: "john@example.com" });
}

const server = new grpc.Server();
server.addService(userProto.UserService.service, { getUser: getUser });
server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
  server.start();
});
```

### Exploitation Steps
1. Identify a sensitive gRPC method (e.g., `getUser`)
2. Try adding a static extension to the endpoint: `/grpc.js`
3. If the server returns the same sensitive data, proceed
4. Check if the response is cached (look for `X-Cache: MISS` on first request, `HIT` on second)
5. If cached, the sensitive data is now accessible via the static URL

### Testing Methods
1. Test various static extensions: `.js`, `.css`, `.ico`
2. Check for caching behavior
3. Verify if the response contains sensitive data

### Fix
```javascript
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const PROTO_PATH = './user.proto';
const packageDefinition = protoLoader.loadSync(PROTO_PATH);
const userProto = grpc.loadPackageDefinition(packageDefinition).user;

function getUser(call, callback) {
  const userId = call.request.id;
  
  // Validate the request
  if (!userId || typeof userId !== 'string') {
    callback({ code: grpc.status.INVALID_ARGUMENT, message: 'Invalid user ID' });
    return;
  }
  
  // Return sensitive user data
  callback(null, { id: userId, name: "John Doe", email: "john@example.com" });
}

const server = new grpc.Server();
server.addService(userProto.UserService.service, { getUser: getUser });
server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {
  server.start();
});
```

---

<a name="prevention"></a>
## Prevention Strategies

### General Prevention Techniques

1. **Consistent URL Normalization**
   - Implement consistent URL normalization across all components
   - Ensure the cache and origin server handle URLs in the same way

2. **Proper Cache Headers**
   - Use `Cache-Control: no-store` for sensitive content
   - Use `Cache-Control: private` for content that should only be cached by browsers

3. **Input Validation**
   - Validate all input, including URL paths
   - Reject suspicious characters and patterns

4. **Cache Key Normalization**
   - Normalize cache keys to ensure consistent behavior
   - Include relevant headers in the cache key

5. **Testing and Monitoring**
   - Regularly test for cache deception vulnerabilities
   - Monitor for unusual cache behavior

### Technology-Specific Prevention

#### For Web Applications
- Use strict routing that doesn't ignore extra path segments
- Implement proper authentication and authorization
- Set appropriate cache headers for different types of content

#### For APIs
- Validate all input parameters
- Use API gateways with proper caching configurations
- Implement rate limiting to prevent abuse

#### For SPAs
- Set appropriate cache headers for the SPA shell
- Implement proper authentication checks
- Use service workers with caution

#### For GraphQL
- Normalize queries before generating cache keys
- Implement proper authentication and authorization
- Use persistent queries to prevent injection

#### For gRPC
- Validate all request parameters
- Implement proper authentication and authorization
- Use interceptors to add security headers

### CDN-Specific Prevention

1. **Cloudflare**
   - Enable "Cache Deception Armor"
   - Use Cloudflare Workers to normalize URLs

2. **Akamai**
   - Configure proper cache rules
   - Use "Path Normalization" feature

3. **AWS CloudFront**
   - Configure proper cache behaviors
   - Use Lambda@Edge to normalize URLs

4. **Fastly**
   - Configure proper cache rules
   - Use VCL to normalize URLs

By implementing these prevention strategies, you can significantly reduce the risk of web cache deception attacks.
