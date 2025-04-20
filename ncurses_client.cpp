/*
 * P3 NCURSES CLIENT
 * ---------------
 * Description: An ncurses-based client for the secure video game rental server
 */

#include <ncurses.h>
#include <form.h>
#include <menu.h>
#include <string>
#include <cstring>
#include <vector>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXDATASIZE 100000
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define CTRLD 4

// Global variables
int sockfd = -1;
SSL* ssl = nullptr;
SSL_CTX* ctx = nullptr;
bool is_connected = false;
bool is_authenticated = false;
std::string current_user;

// Forward declarations
bool connect_to_server(const std::string& server_ip, const std::string& server_port);
void cleanup_connection();
std::string send_command_and_get_response(const std::string& command);
void display_message_box(const std::string& message);
bool username_form();
bool password_form(const std::string& username, bool is_new_user);
void command_interface();

// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD* method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Set TLS 1.3 as the only allowed protocol version
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Clean up OpenSSL
void cleanup_openssl() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
    
    EVP_cleanup();
    ERR_free_strings();
}

// Get sockaddr, IPv4 or IPv6
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Connect to the server
bool connect_to_server(const std::string& server_ip, const std::string& server_port) {
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(server_ip.c_str(), server_port.c_str(), &hints, &servinfo);
    if (rv != 0) {
        return false;
    }

    // Loop through results and connect to the first we can
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == nullptr) {
        return false;
    }

    freeaddrinfo(servinfo);

    // Create SSL object and attach to socket
    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        return false;
    }

    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        close(sockfd);
        return false;
    }

    is_connected = true;
    return true;
}

// Clean up the connection
void cleanup_connection() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }

    if (sockfd != -1) {
        close(sockfd);
        sockfd = -1;
    }

    is_connected = false;
    is_authenticated = false;
}

// Send a command to the server and get the response
std::string send_command_and_get_response(const std::string& command) {
    if (!is_connected || !ssl) {
        return "Not connected to server";
    }

    // Add CRLF to the end of the command (for proper protocol formatting)
    std::string cmd = command + "\r\n";
    
    // Send command
    if (SSL_write(ssl, cmd.c_str(), cmd.length()) <= 0) {
        return "Error sending command to server";
    }

    // Read response
    char buffer[MAXDATASIZE];
    int bytes = SSL_read(ssl, buffer, MAXDATASIZE - 1);
    if (bytes <= 0) {
        return "Error reading response from server";
    }

    buffer[bytes] = '\0';
    return std::string(buffer);
}

// Display a message box with the given message
void display_message_box(const std::string& message) {
    clear();
    int height, width;
    getmaxyx(stdscr, height, width);
    
    WINDOW* win = newwin(10, width - 20, height/2 - 5, 10);
    box(win, 0, 0);
    
    // Add a title border
    wattron(win, A_BOLD);
    mvwprintw(win, 0, (width - 30)/2, " Message ");
    wattroff(win, A_BOLD);
    
    // Add the message with word wrap
    int line = 2;
    std::string temp = message;
    while (!temp.empty() && line < 8) {
        size_t display_len = std::min(temp.length(), (size_t)width - 30);
        if (display_len < temp.length() && temp[display_len] != ' ') {
            // Find the last space before this position for word wrapping
            size_t last_space = temp.substr(0, display_len).find_last_of(' ');
            if (last_space != std::string::npos) {
                display_len = last_space;
            }
        }
        mvwprintw(win, line, 2, "%s", temp.substr(0, display_len).c_str());
        temp.erase(0, display_len);
        if (!temp.empty() && temp[0] == ' ') {
            temp.erase(0, 1);  // Remove the leading space after a wrap
        }
        line++;
    }
    
    mvwprintw(win, 8, 2, "Press any key to continue...");
    
    wrefresh(win);
    wgetch(win);
    
    delwin(win);
    refresh();
}

// Username form - first screen for all users
bool username_form() {
    // Clear entire screen and flush
    clear();
    refresh();
    
    // Create a simple border
    box(stdscr, 0, 0);
    refresh();
    
    // Print title using basic text
    attron(A_BOLD);
    mvprintw(2, 5, "GAME RENTAL SYSTEM");
    attroff(A_BOLD);
    refresh();
    
    // Print login instructions directly
    mvprintw(4, 5, "PLEASE LOGIN OR CREATE AN ACCOUNT");
    refresh();
    
    // Basic instructions with immediate refresh
    mvprintw(5, 5, "Enter your username to login or create a new account");
    refresh();
    
    // Label for input field
    attron(A_BOLD);
    mvprintw(7, 5, "Username:");
    attroff(A_BOLD);
    refresh();
    
    // Draw underline for input field
    for (int i = 0; i < 30; i++) {
        mvaddch(7, 15 + i, '_');
    }
    refresh();
    
    // Instructions at the bottom
    mvprintw(20, 5, "Press ENTER to continue or ESC to exit");
    refresh();
    
    // Direct terminal input without forms
    char username[31] = {0}; // 30 chars + null terminator
    int pos = 0;
    int ch;
    bool result = false;
    
    // Position cursor at start of input field
    move(7, 15);
    curs_set(1); // Make cursor visible
    echo(); // Show typing
    refresh();
    
    // Input loop
    while (true) {
        ch = getch();
        
        if (ch == 27) { // Escape key
            return false;
        }
        else if (ch == 10) { // Enter key
            username[pos] = '\0'; // Ensure null termination
            std::string username_str(username);
            
            // Trim trailing spaces
            if (username_str.find_last_not_of(" \n\r\t") != std::string::npos) {
                username_str.erase(username_str.find_last_not_of(" \n\r\t") + 1);
            } else if (!username_str.empty()) {
                // String contains only whitespace
                username_str = "";
            }
            
            if (username_str.empty()) {
                mvprintw(9, 5, "Username cannot be empty. Please enter a username.");
                move(7, 15 + pos); // Move cursor back to input position
                refresh();
                continue;
            }
            
            // Show checking message
            mvprintw(9, 5, "Checking username...                                  ");
            refresh();
            
            // Send USER command to check if user exists
            std::string user_response = send_command_and_get_response("USER " + username_str);
            
            // Debug screen
            clear();
            box(stdscr, 0, 0);
            attron(A_BOLD);
            mvprintw(2, 5, "USER DETECTION DEBUG");
            attroff(A_BOLD);
            
            mvprintw(4, 5, "Username: %s", username_str.c_str());
            mvprintw(6, 5, "Server Response: %s", user_response.c_str());
            
            // COMPLETELY RESTRUCTURED USER DETECTION LOGIC
            // Extract the response code if possible (first 3 digits)
            std::string response_code = "";
            if (user_response.length() >= 3 && isdigit(user_response[0]) && 
                isdigit(user_response[1]) && isdigit(user_response[2])) {
                response_code = user_response.substr(0, 3);
            }
            
            // IMPORTANT: The server returns 331 for both new and existing users, but with different messages
            // 331 User name okay, need password = EXISTING USER
            // 331 New user, need password to create account = NEW USER
            
            // Default to new user
            bool is_new_user = true;
            
            // Check the exact message text to differentiate
            if (user_response.find("User name okay") != std::string::npos) {
                // This is the message for EXISTING users
                is_new_user = false;
            } 
            else if (user_response.find("New user") != std::string::npos) {
                // This is the message for NEW users
                is_new_user = true;
            }
            // If neither pattern matches, default to treating as new user
            
            bool is_existing_user = !is_new_user;
            
            // Print detailed debug info
            mvprintw(8, 5, "Extracted code: '%s'", response_code.c_str());
            mvprintw(10, 5, "DECISION LOGIC:");
            mvprintw(11, 5, "- If message contains 'User name okay': Existing user");
            mvprintw(12, 5, "- If message contains 'New user': New user");
            mvprintw(13, 5, "- Otherwise: Default to new user");
            
            attron(A_BOLD);
            mvprintw(14, 5, "RESULT:");
            mvprintw(15, 5, "User exists? %s", is_existing_user ? "YES" : "NO");
            mvprintw(16, 5, "New user? %s", is_new_user ? "YES" : "NO");
            mvprintw(17, 5, "Will show: %s", is_new_user ? "CREATE NEW ACCOUNT" : "LOGIN FORM");
            attroff(A_BOLD);
            
            mvprintw(19, 5, "Press any key to continue...");
            refresh();
            getch();
            
            // Show password form with correct user type
            result = password_form(username_str, is_new_user);
            return result;
        }
        else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
            if (pos > 0) {
                pos--;
                // Move cursor back and replace with underscore
                move(7, 15 + pos);
                addch('_');
                // Position cursor at the correct spot
                move(7, 15 + pos);
                refresh();
            }
        }
        else if (pos < 30 && ch >= 32 && ch <= 126) { // Printable characters
            // Store character and display it
            username[pos] = ch;
            mvaddch(7, 15 + pos, ch);
            pos++;
            move(7, 15 + pos); // Move cursor to next position
            refresh();
        }
    }
    
    return result;
}

// Password form - second screen (handles both new and existing users)
bool password_form(const std::string& username, bool is_new_user) {
    // Clear screen completely
    clear();
    refresh();
    
    // Simple border
    box(stdscr, 0, 0);
    refresh();
    
    // Basic title
    attron(A_BOLD);
    mvprintw(2, 5, "GAME RENTAL SYSTEM");
    attroff(A_BOLD);
    refresh();
    
    // User status with better messages for new users
    attron(A_BOLD);
    if (is_new_user) {
        mvprintw(4, 5, "CREATE NEW ACCOUNT");
        mvprintw(5, 5, "Welcome, %s! You're creating a new account.", username.c_str());
    } else {
        mvprintw(4, 5, "USER LOGIN");
        mvprintw(5, 5, "Welcome back, %s! Please enter your password.", username.c_str());
    }
    attroff(A_BOLD);
    refresh();
    
    // Instructions with more details
    if (is_new_user) {
        mvprintw(7, 5, "Please choose a password for your new account");
        mvprintw(8, 5, "(You'll need to enter it twice for verification)");
    } else {
        mvprintw(7, 5, "Please enter your password to log in");
    }
    refresh();
    
    // Password label
    attron(A_BOLD);
    mvprintw(9, 5, "Password:");
    attroff(A_BOLD);
    
    // Draw underline for password field
    for (int i = 0; i < 30; i++) {
        mvaddch(9, 15 + i, '_');
    }
    refresh();
    
    // Confirm password field for new users
    if (is_new_user) {
        attron(A_BOLD);
        mvprintw(11, 5, "Confirm:");
        attroff(A_BOLD);
        
        for (int i = 0; i < 30; i++) {
            mvaddch(11, 15 + i, '_');
        }
        refresh();
    }
    
    // Instructions at the bottom
    if (is_new_user) {
        mvprintw(15, 5, "Press ENTER to create account or ESC to go back");
    } else {
        mvprintw(15, 5, "Press ENTER to login or ESC to go back");
    }
    refresh();
    
    // Direct input for password
    char password[31] = {0}; // 30 chars + null terminator
    char confirm[31] = {0};  // For new users
    int pos = 0;
    int ch;
    
    // Position cursor at start of password field
    move(9, 15);
    curs_set(1); // Make cursor visible
    noecho(); // Don't show password characters
    refresh();
    
    // Input loop for password
    while (true) {
        ch = getch();
        
        if (ch == 27) { // Escape key
            return false;
        }
        else if (ch == 10) { // Enter key
            password[pos] = '\0'; // Ensure null termination
            
            if (pos == 0) {
                // Empty password
                mvprintw(13, 5, "Password cannot be empty. Please enter a password.");
                move(9, 15);
                refresh();
                continue;
            }
            
            if (is_new_user) {
                // Now get confirmation password
                pos = 0;
                
                // Clear any previous message
                move(13, 5);
                clrtoeol();
                refresh();
                
                // Move to confirmation field
                move(11, 15);
                refresh();
                
                // Input loop for confirm password
                while (true) {
                    ch = getch();
                    
                    if (ch == 27) { // Escape key
                        return false;
                    }
                    else if (ch == 10) { // Enter key
                        confirm[pos] = '\0'; // Ensure null termination
                        break;
                    }
                    else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
                        if (pos > 0) {
                            pos--;
                            // Replace with underscore
                            move(11, 15 + pos);
                            addch('_');
                            // Position cursor correctly
                            move(11, 15 + pos);
                            refresh();
                        }
                    }
                    else if (pos < 30 && ch >= 32 && ch <= 126) { // Printable characters
                        confirm[pos] = ch;
                        // Show asterisk instead of character
                        mvaddch(11, 15 + pos, '*');
                        pos++;
                        move(11, 15 + pos);
                        refresh();
                    }
                }
                
                // Check if passwords match
                if (strcmp(password, confirm) != 0) {
                    mvprintw(13, 5, "Passwords do not match. Please try again.");
                    refresh();
                    
                    // Clear password fields
                    for (int i = 0; i < 30; i++) {
                        mvaddch(9, 15 + i, '_');
                        mvaddch(11, 15 + i, '_');
                    }
                    pos = 0;
                    move(9, 15);
                    refresh();
                    continue;
                }
                
                // Show processing message
                clear();
                box(stdscr, 0, 0);
                mvprintw(10, 10, "Creating your new account...");
                refresh();
                
                // Send USER command first to start session
                std::string user_cmd_response = send_command_and_get_response("USER " + username);
                
                // Send NEWUSER command to create the account
                std::string newuser_response = send_command_and_get_response("NEWUSER " + username);
                
                // Check if account creation was successful
                if (newuser_response.find("230") == std::string::npos) {
                    mvprintw(12, 10, "Failed to create account: %s", newuser_response.c_str());
                    mvprintw(14, 10, "Press any key to continue...");
                    refresh();
                    getch();
                    return false;
                }
                
                // Send PASS command to set the password for the new account
                std::string pass_response = send_command_and_get_response("PASS " + std::string(password));
                
                // Check if password was set successfully
                if (pass_response.find("230") != std::string::npos) {
                    clear();
                    box(stdscr, 0, 0);
                    mvprintw(10, 10, "Account created successfully!");
                    mvprintw(11, 10, "Welcome to the Game Rental System!");
                    mvprintw(13, 10, "Press any key to continue...");
                    refresh();
                    getch();
                    
                    is_authenticated = true;
                    current_user = username;
                    return true;
                } else {
                    clear();
                    box(stdscr, 0, 0);
                    mvprintw(10, 10, "Account created but password setting failed: %s", pass_response.c_str());
                    mvprintw(12, 10, "Press any key to continue...");
                    refresh();
                    getch();
                    return false;
                }
            } else {
                // Show login message for existing user
                clear();
                box(stdscr, 0, 0);
                mvprintw(10, 10, "Verifying your login credentials...");
                refresh();
                
                // Send PASS command with password
                std::string pass_response = send_command_and_get_response("PASS " + std::string(password));
                
                // Check if login was successful
                if (pass_response.find("230") != std::string::npos) {
                    clear();
                    box(stdscr, 0, 0);
                    mvprintw(10, 10, "Login successful!");
                    mvprintw(11, 10, "Welcome back to the Game Rental System!");
                    mvprintw(13, 10, "Press any key to continue...");
                    refresh();
                    getch();
                    
                    is_authenticated = true;
                    current_user = username;
                    return true;
                } else {
                    clear();
                    box(stdscr, 0, 0);
                    mvprintw(10, 10, "Login failed: %s", pass_response.c_str());
                    mvprintw(12, 10, "Press any key to continue...");
                    refresh();
                    getch();
                    return false;
                }
            }
        }
        else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
            if (pos > 0) {
                pos--;
                // Replace with underscore
                move(9, 15 + pos);
                addch('_');
                // Position cursor correctly
                move(9, 15 + pos);
                refresh();
            }
        }
        else if (pos < 30 && ch >= 32 && ch <= 126) { // Printable characters
            password[pos] = ch;
            // Show asterisk instead of character
            mvaddch(9, 15 + pos, '*');
            pos++;
            move(9, 15 + pos);
            refresh();
        }
    }
    
    return false;
}

// Command interface - simple version
void command_interface() {
    clear();
    
    // Create simple window layout
    box(stdscr, 0, 0);
    
    // Draw headers without conditional colors
    attron(A_BOLD);
    mvprintw(2, 2, "GAME RENTAL SYSTEM - LOGGED IN AS: %s", current_user.c_str());
    attroff(A_BOLD);
    
    mvprintw(4, 2, "Type commands and press Enter. Type 'HELP' for list of commands.");
    mvprintw(5, 2, "Type 'EXIT' to log out and exit.");
    
    // Draw separator
    for (int i = 1; i < COLS-1; i++) {
        mvaddch(6, i, '-');
    }
    
    // Main command loop
    char cmd_buf[256];
    int current_line = 8;
    int max_display_line = LINES - 4;
    
    // Display help at start
    std::string help_response = send_command_and_get_response("HELP");
    attron(A_BOLD);
    mvprintw(current_line++, 2, "Available commands:");
    attroff(A_BOLD);
    
    std::istringstream help_stream(help_response);
    std::string line;
    while (std::getline(help_stream, line)) {
        mvprintw(current_line++, 4, "%s", line.c_str());
        if (current_line >= max_display_line) {
            current_line = 8; // Reset if we've filled the screen
            mvprintw(LINES-2, 2, "Press any key to continue...");
            getch();
            // Clear command area
            for (int i = 8; i < max_display_line; i++) {
                move(i, 1);
                clrtoeol();
            }
        }
    }
    
    current_line += 2;
    
    // Position for command input
    while (true) {
        // Move to command line
        attron(A_BOLD);
        mvprintw(LINES-3, 2, "Command: ");
        attroff(A_BOLD);
        clrtoeol(); // Clear any previous command
        
        // Make sure cursor is visible
        curs_set(1);
        move(LINES-3, 11); // Position at command input
        refresh();
        
        // Get user input
        echo(); // Show typing
        getnstr(cmd_buf, 255);
        noecho(); // Hide typing for next iteration
        
        std::string command(cmd_buf);
        
        // Handle exit
        if (command == "EXIT" || command == "exit") {
            clear();
            box(stdscr, 0, 0);
            mvprintw(LINES/2, COLS/2 - 10, "Logging out... Goodbye!");
            refresh();
            napms(1500); // Show goodbye message for 1.5 seconds
            break;
        }
        
        // Scroll screen if needed
        if (current_line >= max_display_line - 5) { // Leave room for response
            // Clear command area
            for (int i = 8; i < max_display_line; i++) {
                move(i, 1);
                clrtoeol();
            }
            current_line = 8;
        }
        
        // Show command
        attron(A_BOLD);
        mvprintw(current_line++, 2, "> %s", command.c_str());
        attroff(A_BOLD);
        
        // Process command
        std::string response = send_command_and_get_response(command);
        
        // Display response
        std::istringstream iss(response);
        std::string resp_line;
        while (std::getline(iss, resp_line)) {
            if (current_line >= max_display_line - 1) {
                mvprintw(LINES-2, 2, "Press any key to continue...");
                getch();
                
                // Clear command area
                for (int i = 8; i < max_display_line; i++) {
                    move(i, 1);
                    clrtoeol();
                }
                current_line = 8;
                
                // Show command again as context
                attron(A_BOLD);
                mvprintw(current_line++, 2, "> %s (continued)", command.c_str());
                attroff(A_BOLD);
            }
            
            mvprintw(current_line++, 4, "%s", resp_line.c_str());
        }
        
        current_line++; // Add a blank line after each command response
    }
    
    // Exit command interface
    clear();
}

// Main function
int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " client.conf" << std::endl;
        return 1;
    }
    
    // Read configuration from file
    std::string server_ip, server_port;
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening config file: " << argv[1] << std::endl;
        return 1;
    }
    
    std::string line;
    while (std::getline(configFile, line)) {
        if (line.find("SERVER_IP=") == 0) {
            server_ip = line.substr(10);
        } else if (line.find("SERVER_PORT=") == 0) {
            server_port = line.substr(12);
        }
    }
    configFile.close();
    
    if (server_ip.empty() || server_port.empty()) {
        std::cerr << "Invalid config file format." << std::endl;
        return 1;
    }
    
    // Initialize OpenSSL
    init_openssl();
    
    // Initialize ncurses with proper settings
    initscr();            // Start ncurses mode
    cbreak();             // Line buffering disabled
    noecho();             // Don't echo keystrokes
    keypad(stdscr, TRUE); // Enable function keys and arrow keys
    
    // Make sure cursor is visible
    curs_set(1);
    
    // Enable color if terminal supports it
    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_WHITE, COLOR_BLUE);     // For titles
        init_pair(2, COLOR_GREEN, COLOR_BLACK);    // For success messages
        init_pair(3, COLOR_RED, COLOR_BLACK);      // For error messages
        init_pair(4, COLOR_YELLOW, COLOR_BLACK);   // For warnings/highlights
    }
    
    // Connect to the server
    if (!connect_to_server(server_ip, server_port)) {
        endwin();
        std::cerr << "Failed to connect to server at " << server_ip << ":" << server_port << std::endl;
        cleanup_openssl();
        return 1;
    }
    
    // Show username form first
    bool login_success = username_form();
    
    // If login is successful, show command interface
    if (login_success) {
        command_interface();
    }
    
    // Clean up and exit
    cleanup_connection();
    cleanup_openssl();
    endwin();
    
    return 0;
} 