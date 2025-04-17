# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands
- Compile server and client: `make` 
- Compile server only: `make server`
- Compile client only: `make client`
- Clean binaries: `make clean`
- Run server: `./server server.conf`
- Run client: `./client client.conf`
- Test TLS connection: `openssl s_client -connect server_ip:server_port -tls1_3`

## P3 Security Requirements
- Implement TLS 1.3 with OpenSSL 3.2.2+
- Replace HELO with USER/PASS authentication
- Add secure password generation (8-char, complex)
- Use PBKDF2-HMAC-SHA256 for password hashing (10,000 iterations)
- Store credentials in `.games_shadow` file
- Implement new user registration protocol
- Handle authentication with 2-failure lockout
- Generate self-signed certs (p3server.key, p3server.crt)

## Code Style Guidelines
- C++20 standard with STL containers and algorithms
- Follow Google C++ Style Guide 
- Error handling with perror and std::system_error
- Thread-safe code with mutexes for shared data
- Naming: descriptive names, camelCase for variables, PascalCase for structs
- Format strings with std::format
- Code should be at the level of a 4th year CS undergraduate student:
  - Moderate commenting (not excessive)
  - Clear but not overly complex code structure
  - Use good practices but avoid expert-level techniques
  - Show competence but not expert mastery

## Project Organization
- Server handles requests in separate threads (thread-per-connection model)
- Command handlers follow function-based design pattern
- Data structures: Game, RentalRecord, RatingData
- Global maps for user history and ratings with mutex protection
- Socket programming with proper cleanup

## Project Scope
- Only the server code will be submitted/graded
- Client code is provided but not part of the submission

## Protocol Commands
- Authentication: USER, PASS (replacing HELO)
- Core modes: BROWSE, RENT, MYGAMES
- Browse mode: LIST, SEARCH, SHOW
- Rent mode: CHECKOUT, RETURN
- MyGames mode: HISTORY, RECOMMEND, RATE
- Connection: HELP, BYE