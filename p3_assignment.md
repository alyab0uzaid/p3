# EB 3140 CS447-00x Spring 2025

## CS447-00x: Networks and Data Communications  
### Programming Assignment #1 (P3)  

**Total Points**: 100 
**Assigned Date**: Wednesday, April 10, 2025  
**Due Date**: Thursday, April 24, 2025 @ 01:59:59 p.m. (hard deadline)

---

## Overview

Building upon the video games rental system from P1, you will now enhance its security. This assignment focuses on implementing security mechanisms to protect the system from unauthorized access and ensure data confidentiality and integrity. You will implement Transport Layer Security (TLS) for secure communication, a secure login system, an authentication protocol, a secure password generator, and learn how to protect sensitive data at rest.

**Note**: This final assignment has a hard deadline and does not include the typical 48-hour late penalty period.

### Learning Objectives

- Gain practical experience with OpenSSL for TLS implementation, secure password hashing, and data encryption.  
- Understand the importance of secure password management and implement techniques for generating, storing, and transmitting passwords securely.  
- Develop skills in securing network applications and protecting sensitive data in transit and at rest.

---

## Back Story

Captain Haddock’s ingenious video game system, a welcome respite on the open sea, was infiltrated by a mysterious entity known as “The Kraken.”  
Tintin recognized the danger and demanded Calculus secure their system. Calculus must now implement TLS encryption, secure logins, and protected data storage.

---

## Technical Requirements

All P1 technical requirements apply to P3. Additional new requirements:

### 1. Secure Communication

- Use TLS 1.3 with OpenSSL 3.2.2+.
- Set protocol version to TLS 1.3 using `SSL_CTX_set_min_proto_version()` and `SSL_CTX_set_max_proto_version()`.
- Choose strong cipher suites using `SSL_CTX_set_ciphersuites()`.
- Generate self-signed certs as `p3server.key` and `p3server.crt`.

### 2. Secure Login System

- Replace `HELO` with `USER <username>` and `PASS <password>` commands.

### 3. Password & Salt Generation

- Generate 8-character random password with required complexity.
- Use 16-byte unique salt using OpenSSL `RAND_bytes()`.

### 4. Password Hashing/Key Derivation

- Use PBKDF2-HMAC-SHA256 with:
  - 16-byte salt
  - 10,000 iterations
  - 32-byte hash
  - OpenSSL’s `PKCS5_PBKDF2_HMAC()`

### 5. Secure Credential Storage

- Store in `.games_shadow` using:
  `username:$pbkdf2-sha256$work_factor$salt_base64$hash_base64`
- Base64-encode salt and hash.

### 6. New User Registration Protocol

- Triggered on unknown USER command:
  - Generate password and salt
  - Hash password
  - Store credentials
  - Send password over TLS
  - Close connection

### 7. Authentication Protocol

- Triggered after known USER and PASS:
  - Retrieve and decode stored hash/salt
  - Hash received password
  - Compare with stored hash
  - On success: respond and keep open
  - On 2 failures: respond and close

---

## Functional Requirements

- Fix P1 issues
- Use `openssl s_client -connect server_ip:server_port -tls1_3`
- Handle multiple concurrent clients
- Provide proof of TLS via Wireshark or .pcap
- `.games_shadow` must persist and reload

---

## Extra Credit

Optional +20% for ncurses-based secure client with TUI  
[https://www.gnu.org/software/ncurses/](https://www.gnu.org/software/ncurses/)

---

## Instructions

- Start early, backup work
- Follow coding standards like [Google C++ Style Guide](https://google.github.io/styleguide/)
- Must compile and run in Linux
- Submit C++ source, report, .tgz archive
- Avoid unapproved libraries
- Submit via Moodle by deadline

---

## Deliverables

### 1. Report (PDF)

- Introduction  
- Design  
- Sample Run  
- Proof  
- Summary

### 2. Compressed tarball (siue-id-p3.tgz)

- C++ source (exclude client unless extra credit)
- Makefile
- README
- .pcap file

Create using:  
`tar -zcvf siue-id-p3.tgz p3/`

---

## Academic Integrity

- Do not copy code. MOSS will be used: [http://theory.stanford.edu/~aiken/moss/](http://theory.stanford.edu/~aiken/moss/)
- Cite sources. Implement your own version.
- Plagiarism = failing grade.

---

## Useful Resources

- Linux Man Pages  
- [Beej’s Guide to Network Programming](https://beej.us/guide/bgnet/)  
- [Linux Socket Programming in C++](https://tldp.org/LDP/LG/issue74/tougher.html)  
- [Linux HOWTO Socket](https://www.linuxhowtos.org/C_C++/socket.htm)  
- [Makefile Tutorial](https://makefiletutorial.com/)  
- [Fedora Defensive Coding](https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/index.html)  
- [OpenSSL Simple TLS Server](https://wiki.openssl.org/index.php/Simple_TLS_Server)  
- [TLS 1.3 Guide](https://tls13.xargs.org/)  
- [Readable TLS 1.3](https://www.davidwong.fr/tls13/)  
- [Create SSL Cert](https://linuxize.com/post/creating-a-self-signed-ssl-certificate/)  
- [Ncurses Guide](http://jbwyatt.com/ncurses.html)
