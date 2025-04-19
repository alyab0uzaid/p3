README

CS447 Spring 2025 P3: Secure Game Rental System
=================================
Author: Thoshitha Gamage
Modified by: Aly Abou-Zaid
Date: April 19, 2025

Overview:
This project implements a secure video game rental system with a client-server architecture using TLS 1.3 for encrypted communication. The server manages game listings, rentals, returns, ratings, and recommendations, while supporting secure user authentication and credential storage.

Security Features:
- TLS 1.3 encryption using OpenSSL
- Secure password hashing with PBKDF2-HMAC-SHA256
- Secure credential storage in .games_shadow file
- User registration and authentication protocol

Files:
  |- server.cpp: Server application with TLS support and user authentication
  |- client.cpp: Basic client application for testing
  |- Makefile: Makefile to compile the server and client applications
  |- server.conf: Configuration file for the server (port number)
  |- client.conf: Configuration file for the client (server IP and port)
  |- games.db: Text file containing the video game database
  |- p3server.key: TLS private key
  |- p3server.crt: TLS certificate
  |- .games_shadow: Secure storage for user credentials

Instructions:
  1. To compile the project, run: make
  2. Configure the server.conf and client.conf files with the appropriate port number and server IP address
  3. Start the server with: ./server server.conf
  4. You can connect to the server using the OpenSSL client:
     openssl s_client -tls1_3 -quiet -connect <server_ip>:<port>
     
     Note: The -quiet option is required to prevent OpenSSL from interpreting the "R" in "RENT" 
     as a renegotiation command.

Authentication Commands:
  - USER <username>: Initiate login with username
  - PASS <password>: Authenticate with password
  
After Authentication:
  - BROWSE: Switch to browse mode to search the game catalog
  - RENT: Switch to rent mode to check out and return games
  - MYGAMES: Switch to personal mode to view history and recommendations
  - HELP: Display available commands for the current mode
  - BYE: End the session

Note: For detailed usage information, use the HELP command after connecting to the server.
