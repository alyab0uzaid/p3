/*
 * P1 SAMPLE CLIENT
 * ---------------
 * Author: Thoshitha Gamage
 * Date: 01/29/2025
 * License: MIT License
 * Description: This is a sample code for CS447 Spring 2025 P1 client code.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <optional>
#include <filesystem>
#include <format>
#include <array>

constexpr size_t MAXDATASIZE = 100000;

// Add a helper function to directly test authentication flow
bool test_authentication(SSL* ssl, const std::string& username, const std::string& password) {
    std::cout << "\n=== Testing Authentication Flow ===\n";
    
    // Send USER command
    std::string user_cmd = "USER " + username + "\r\n";
    std::cout << "Sending: " << user_cmd;
    if (SSL_write(ssl, user_cmd.c_str(), user_cmd.length()) <= 0) {
        std::cerr << "Error sending USER command\n";
        return false;
    }
    
    // Read USER response
    std::array<char, MAXDATASIZE> buffer;
    int bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
    if (bytes <= 0) {
        std::cerr << "Error reading USER response\n";
        return false;
    }
    buffer[bytes] = '\0';
    std::cout << "Received (" << bytes << " bytes): " << buffer.data() << std::endl;
    
    // Send PASS command
    std::string pass_cmd = "PASS " + password + "\r\n";
    std::cout << "Sending: " << pass_cmd;
    if (SSL_write(ssl, pass_cmd.c_str(), pass_cmd.length()) <= 0) {
        std::cerr << "Error sending PASS command\n";
        return false;
    }
    
    // Read PASS response with retry logic
    bytes = 0;
    for (int i = 0; i < 10; i++) {  // Try up to 10 times with delays
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
        if (bytes > 0) break;
        std::cout << "No response yet, retrying... (" << i+1 << "/10)\n";
    }
    
    if (bytes <= 0) {
        std::cerr << "Error reading PASS response after multiple attempts\n";
        // Dump SSL errors
        int err = SSL_get_error(ssl, bytes);
        std::cerr << "SSL error code: " << err << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    buffer[bytes] = '\0';
    std::cout << "Received (" << bytes << " bytes): " << buffer.data() << std::endl;
    
    // Send HELP command to test if authentication worked
    std::string help_cmd = "HELP\r\n";
    std::cout << "Sending: " << help_cmd;
    if (SSL_write(ssl, help_cmd.c_str(), help_cmd.length()) <= 0) {
        std::cerr << "Error sending HELP command\n";
        return false;
    }
    
    // Read HELP response with retry logic
    bytes = 0;
    for (int i = 0; i < 10; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
        if (bytes > 0) break;
        std::cout << "No response yet, retrying... (" << i+1 << "/10)\n";
    }
    
    if (bytes <= 0) {
        std::cerr << "Error reading HELP response\n";
        return false;
    }
    
    buffer[bytes] = '\0';
    std::cout << "HELP response (" << bytes << " bytes):\n";
    std::cout << "===================\n";
    std::cout << buffer.data();
    std::cout << "===================\n";
    
    return true;
}

// Get sockaddr, IPv4 or IPv6
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char* argv[]) {
    if (argc!= 2) {
        std::cerr << "usage: client client.conf\n";
        return 1;
    }

    // Read configuration from file
    std::optional<std::string> serverIP, serverPort;
    std::filesystem::path configFilePath(argv[1]);

    if (!std::filesystem::is_regular_file(configFilePath)) {
        std::cerr << std::format("Error opening config file: {}\n", *argv);
        return 1;
    }

    std::ifstream configFile(argv[1]);
    std::string line;
    while (std::getline(configFile, line)) {
        if (line.find("SERVER_IP=") == 0) {
            serverIP = line.substr(10);
        } else if (line.find("SERVER_PORT=") == 0) {
            serverPort = line.substr(12);
        }
    }
    configFile.close();

    if (!serverIP.has_value() ||!serverPort.has_value()) {
        std::cerr << "Invalid config file format.\n";
        return 1;
    }

    // Set up connection hints
    addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get address information
    int rv = getaddrinfo(serverIP->c_str(), serverPort->c_str(), &hints, &servinfo);
    if (rv!= 0) {
        std::cerr << std::format("getaddrinfo: {}\n", gai_strerror(rv));
        return 1;
    }

    int sockfd;
    // Loop through results and try to connect
    for (p = servinfo; p!= nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == nullptr) {
        std::cerr << "client: failed to connect\n";
        return 2;
    }

    // Display connection information
    char s[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    std::cout << std::format("client: connecting to {}\n", s);

    freeaddrinfo(servinfo);

    std::array<char, MAXDATASIZE> buf;
    std::string userInput;

    // Show menu options
    std::cout << "\n=== CLIENT MENU ===\n";
    std::cout << "1: Run automated authentication test\n";
    std::cout << "2: Interactive mode\n";
    std::cout << "Choice: ";
    
    int menu_choice = 0;
    std::cin >> menu_choice;
    std::cin.ignore(); // Clear newline
    
    if (menu_choice == 1) {
        // Prompt for test credentials
        std::string test_user, test_pass;
        std::cout << "Enter username to test: ";
        std::getline(std::cin, test_user);
        std::cout << "Enter password to test: ";
        std::getline(std::cin, test_pass);
        
        if (test_authentication(ssl, test_user, test_pass)) {
            std::cout << "\nAuthentication test PASSED! You can now use interactive mode.\n\n";
        } else {
            std::cout << "\nAuthentication test FAILED! Check server logs for details.\n\n";
        }
    }
    
    // Interactive loop for sending and receiving messages
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, userInput);

        if (userInput == "exit") {
            break; // Exit the loop if the user types "exit"
        }

        // Add CRLF to the end of the command (for proper protocol formatting)
        std::string command = userInput + "\r\n";
        
        // Send via SSL
        if (SSL_write(ssl, command.c_str(), command.length()) <= 0) {
            std::cerr << "Error sending command via SSL\n";
            break;
        }

        // Read response with retry logic
        std::memset(buf.data(), 0, MAXDATASIZE);
        int total_bytes = 0;
        bool received_data = false;
        
        // Wait for response
        std::cout << "Waiting for server response...\n";
        for (int attempts = 0; attempts < 5; attempts++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            
            int bytes = SSL_read(ssl, buf.data() + total_bytes, MAXDATASIZE - total_bytes - 1);
            if (bytes > 0) {
                total_bytes += bytes;
                buf[total_bytes] = '\0';
                received_data = true;
                break; // Got data, exit retry loop
            }
        }
        
        if (received_data) {
            std::cout << "Server response:\n-------------------\n";
            std::cout << buf.data();
            std::cout << "\n-------------------\n";
        } else {
            std::cout << "No response received from server\n";
        }
    }

    // Clean shutdown of SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    cleanup_openssl();
    
    return 0;
}

