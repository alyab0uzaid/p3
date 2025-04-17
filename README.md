README

CS447 Spring 2025 P1
=================================
Author: Thoshitha Gamage
Modified by: Aly Abou-Zaid
Date: January 29, 2025

Overview:
This project implements a video game rental system with a client-server architecture. The server manages game listings, rentals, returns, ratings, and recommendations, while the client interacts using a command-based protocol.

Files:
  |- server.cpp: Starter code for the server application.
  |- client.cpp: Starter code for the client application.
  |- Makefile: Makefile to compile the server and client applications.
  |- server.conf: Configuration file for the server (port number).
  |- client.conf: Configuration file for the client (server IP and port).
  |- games.db: Text file containing the video game database.

Instructions:
  1. To compile the project, run: make
  2. Configure the server.conf and client.conf files with the appropriate port number and server IP address.
  3. Start the server with: ./server server.conf
  4. Run the client application with: ./client client.conf
