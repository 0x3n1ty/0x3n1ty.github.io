---
title: Race Conditions - Comprehensive Guide
date: 2025-11-30
category: guides
tags: web
---

## Table of Contents
1. [Introduction to Race Conditions](#introduction)
2. [Types of Race Conditions](#types)
3. [Detection and Exploitation Techniques](#detection)
4. [Tools and Methods for Testing](#tools)
5. [Prevention Strategies](#prevention)
6. [Real-World Examples and Labs](#examples)
7. [Summary Tables](#summary)

<a name="introduction"></a>
## Introduction to Race Conditions

### What Are Race Conditions?
Race conditions occur when multiple processes or threads access shared resources concurrently, and the final outcome depends on the timing of these accesses. In web applications, this can lead to security vulnerabilities when operations that should be atomic are implemented as multiple separate steps.

### Why Are They Dangerous?
- Can bypass business logic constraints
- May lead to privilege escalation
- Can result in financial loss
- Often difficult to detect and reproduce
- Can be exploited to bypass security controls

<a name="types"></a>
## Types of Race Conditions

### 1. Limit Overrun Race Conditions (TOCTOU)
These occur when an application checks a condition and then performs an action based on that check, but the condition changes between the check and the action.

**Examples:**
- Redeeming a gift card multiple times
- Rating a product multiple times
- Withdrawing or transferring cash in excess of account balance
- Reusing a single CAPTCHA solution
- Bypassing anti-brute-force rate limits

### 2. Single-Endpoint Race Conditions
These occur within a single request processing flow where multiple operations are performed sequentially.

**Example: Password Reset Race Condition**
```
Attacker - send reset-password request
A1. Server takes [reset-email] and pause
Victim - send reset-password request
V1. Server overwrites the [reset-email] from attacker's email to victim's mail
V2. Server set [reset-token] for victim's mail
A2. Resume, [reset-token] changes to attacker's token but the token's associated mail is victim's
```

### 3. Multi-Endpoint Race Conditions
These occur when multiple requests to different endpoints interact in unexpected ways.

**Example: Shopping Cart Race Condition**
```
basket pending -> payment processing -> payment validated -> basket confirmed
```
During the race window between payment validation and order confirmation, an attacker can add more items to their basket.

### 4. Partial Construction Race Conditions
These occur when an object is created in multiple steps, leaving a temporary incomplete or insecure state.

**Examples:**
- User registration where API key, role, or password is not yet set
- Order creation where payment status is not finalized
- Token generation where token field is temporarily NULL

### 5. Time-Sensitive Attacks
These occur when security tokens are generated using predictable values like timestamps.

<a name="detection"></a>
## Detection and Exploitation Techniques

### Methodology: Predict -> Probe -> Prove

#### Predict
1. Identify if the endpoint is security critical
2. Determine if there's collision potential (requests affecting the same record)

#### Probe
1. Send a group of requests in sequence using separate connections
2. Send the same group of requests at once using single-packet attack or last-byte sync
3. Observe changes in the response

#### Prove the Concept
1. Understand what's happening
2. Remove superfluous requests
3. Ensure you can replicate the effects

### Timing Challenges
- Network latency
- Server-side jitter
- Internal processing delays

<a name="tools"></a>
## Tools and Methods for Testing

### Burp Repeater
- **Last-Byte Synchronization (HTTP/1)**: Burp delays the final byte of each request and sends all final bytes at the exact same time
- **Single-Packet Attack (HTTP/2)**: Burp sends 20-30 requests packed into one TCP packet

### Turbo Intruder
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    # Queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # Send all requests in gate '1' in parallel
    engine.openGate('1')
```

### Connection Warming
Before sending actual attack requests, add a harmless request to "warm up" the connection and eliminate startup delays.

### HTTP Version Comparison

| HTTP Version | Technique Used | Connections/Streams | Race Window | Reliability |
|--------------|----------------|---------------------|-------------|-------------|
| 1.1          | Last-byte sync | Multiple connections | High        | Very high   |
| 2            | Single-packet  | Multiple streams     | High        | High        |

<a name="prevention"></a>
## Prevention Strategies

### Database-Level Protection
1. **Atomic Operations or Transactions**: Perform checks and updates in a single atomic step
2. **Unique Constraints**: Prevent duplicate entries or states
3. **Database-Level Locks**: Ensure only one request can check and update a record at a time

### Application-Level Protection
1. **Queueing or Synchronization**: Force serialized request processing per user or session
2. **Stateless Architecture**: Use signed JWTs where appropriate
3. **Avoid Storage Mixing**: Don't use session + DB together for sensitive data

### Secure Coding Practices
1. **Consistent Session Handling**: Update session data in a single step or with locking
2. **Proper Input Validation**: Sanitize and validate all user input types and structures
3. **Secure Token Generation**: Use cryptographically secure random number generators (CSPRNG)

<a name="examples"></a>
## Real-World Examples and Labs

### Lab 1: Limit Overrun Race Conditions
**Scenario**: Exploiting a one-time discount code
**Steps**:
1. Send the promo code application request to Burp Repeater
2. Use Ctrl+R to duplicate 16 tabs
3. Group the tabs and select "Send in parallel" (single-packet attack)
4. Send the requests to exploit the race condition

### Lab 2: Bypassing Rate Limits via Race Conditions
**Scenario**: Bypassing login rate limits
**Steps**:
1. Send the login request to Turbo Intruder
2. Use Python code with a password list
3. Add payload position like `password=%s` and `username=carlos`
4. Start the attack and look for 302 Found response
5. Login with the Carlos account and delete the user

### Lab 3: Multi-Endpoint Race Conditions
**Scenario**: Buying an expensive item with insufficient store credit
**Steps**:
1. Add a cheap item to your cart that you can afford
2. In Burp Repeater, prepare three requests:
   - A GET request to warm up the connection
   - A POST request to add the expensive item
   - A POST request to checkout
3. Send all requests in parallel with single-packet attack
4. If successful, you'll have purchased both items while only paying for the cheap one

### Lab 4: Single-Endpoint Race Conditions
**Scenario**: Claiming another user's admin privileges
**Steps**:
1. Send two parallel requests to update your email to the target's email
2. If successful, you'll receive the confirmation email for the target's account
3. Use the confirmation link to gain admin privileges

### Lab 5: Exploiting Time-Sensitive Vulnerabilities
**Scenario**: Predictable password reset tokens
**Steps**:
1. Request password reset tokens for two different accounts simultaneously
2. If tokens are generated using timestamps, they might be identical
3. Use the token received for your account to reset the target's password

<a name="summary"></a>
## Summary Tables

### Race Condition Types and Characteristics

| Type | Description | Common Examples | Detection Method |
|------|-------------|-----------------|-----------------|
| Limit Overrun | Exceeding limits imposed by business logic | Discount codes, rate limits | Parallel requests |
| Single-Endpoint | Within a single request processing flow | Password reset, email change | Timing attacks |
| Multi-Endpoint | Across multiple requests to different endpoints | Shopping cart, payment processing | Request sequencing |
| Partial Construction | During object creation with multiple steps | User registration, API key generation | State inspection |
| Time-Sensitive | Based on predictable token generation | Timestamp-based tokens | Token analysis |

### Prevention Techniques by Race Condition Type

| Type | Prevention Techniques |
|------|----------------------|
| Limit Overrun | Atomic operations, database locks, unique constraints |
| Single-Endpoint | Proper session handling, atomic transactions |
| Multi-Endpoint | Request synchronization, state validation |
| Partial Construction | Atomic object creation, NOT NULL constraints |
| Time-Sensitive | Secure random token generation, proper validation |

### HTTP Protocol Support for Race Condition Testing

| HTTP Version | Support for Race Testing | Recommended Technique |
|--------------|-------------------------|-----------------------|
| HTTP/1.1 | Requires multiple connections | Last-byte synchronization |
| HTTP/2 | Native multiplexing support | Single-packet attack |
| HTTP/3 | Similar to HTTP/2 with QUIC | Single-packet attack |

---

## Key Takeaways

1. **Race conditions are timing-dependent vulnerabilities** that can be difficult to detect and reproduce.
2. **Multiple techniques are available** for testing, including Burp Repeater and Turbo Intruder.
3. **Prevention requires a defense-in-depth approach** with both database and application-level protections.
4. **Connection warming can improve reliability** of race condition attacks.
5. **Session-based locking mechanisms** can mask vulnerabilities - try different session tokens.
6. **Time-based token generation is inherently insecure** - use cryptographically secure random generators instead.

---

## Further Reading

- [OWASP Race Conditions](https://owasp.org/www-community/vulnerabilities/Race_Conditions)
- [PortSwigger Web Security Academy: Race Conditions](https://portswigger.net/web-security/race-conditions)
- [Understanding TOCTOU Vulnerabilities](https://cwe.mitre.org/data/definitions/367.html)
