# Vulnerable PHP Application Demo

This is an educational web application that demonstrates common web security vulnerabilities and their corresponding secure implementations. The project is designed for learning purposes to help developers understand how various security vulnerabilities work and how to prevent them.

⚠️ **WARNING**: This application intentionally contains security vulnerabilities for educational purposes. DO NOT deploy this on a public server or in a production environment.

## Features

The application demonstrates three common web security vulnerabilities:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Directory Traversal

Each vulnerability comes with both a vulnerable and secure implementation for comparison.

## Prerequisites

- PHP 7.0 or higher
- MySQL/MariaDB
- Web server (Apache/Nginx)
- jQuery (included via CDN)

## Installation

1. Clone this repository to your web server directory:
```bash
git clone https://github.com/Pargat-Dhanjal/Secure-Coding-IA-2
cd Secure-Coding-IA-2
```

2. Create a MySQL database and user:
```sql
CREATE DATABASE phpvuln;
CREATE USER 'root'@'localhost' IDENTIFIED BY '7503';
GRANT ALL PRIVILEGES ON phpvuln.* TO 'root'@'localhost';
FLUSH PRIVILEGES;
```

3. Create the required table:
```sql
USE phpvuln;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);
```

4. Add some test data:
```sql
INSERT INTO users (username, password) VALUES 
('admin', 'password123'),
('user', 'userpass');
```

5. Configure your web server to serve the application.

## Usage

The application provides a web interface with three sections, each demonstrating a different vulnerability:

### 1. SQL Injection Testing
- Input fields for username and password
- Tests both vulnerable and secure login implementations
- Try SQL injection payloads like: `' OR '1'='1`

### 2. XSS Testing
- Input field for entering messages
- Tests both vulnerable and secure message display
- Try XSS payloads like: `<script>alert('XSS')</script>`

### 3. Directory Traversal Testing
- Input field for filename
- Tests both vulnerable and secure file access
- Try traversal payloads like: `../../../etc/passwd`

## Security Features

Each vulnerability type includes two implementations:

### SQL Injection Protection
- Vulnerable version uses string concatenation
- Secure version uses prepared statements with parameterized queries

### XSS Protection
- Vulnerable version outputs raw user input
- Secure version uses `htmlspecialchars()` for output encoding

### Directory Traversal Protection
- Vulnerable version allows unrestricted file access
- Secure version validates paths and uses `realpath()`

## Best Practices

1. Never use the vulnerable implementations in production code
2. Always validate and sanitize user input
3. Use prepared statements for database queries
4. Implement proper output encoding
5. Validate file paths and restrict access to allowed directories


## Authors

- [@jsbhumra](https://github.com/jsbhumra)
- [@Pargat-Dhanjal](https://www.github.com/octokatherine)
- [@Beetroot16](https://github.com/Beetroot16)
