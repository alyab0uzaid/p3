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
    
    // Get screen dimensions
    int height, width;
    getmaxyx(stdscr, height, width);
    
    // Create a main border
    box(stdscr, 0, 0);
    refresh();
    
    // Calculate centered positions - make the form wider
    int form_width = 70;  // Increased from 50 to 70
    int form_height = 14; // Increased from 12 to 14
    int start_x = (width - form_width) / 2;
    int start_y = (height - form_height) / 2;
    
    // Create centered form window with border
    WINDOW* form_win = newwin(form_height, form_width, start_y, start_x);
    box(form_win, 0, 0);
    
    // Print title using bold centered text
    wattron(form_win, A_BOLD);
    mvwprintw(form_win, 0, (form_width - 19) / 2, " GAME RENTAL SYSTEM ");
    wattroff(form_win, A_BOLD);
    
    // Print login instructions centered
    wattron(form_win, A_BOLD);
    mvwprintw(form_win, 2, (form_width - 30) / 2, "PLEASE LOGIN OR CREATE AN ACCOUNT");
    wattroff(form_win, A_BOLD);
    
    // Basic instructions centered
    mvwprintw(form_win, 4, (form_width - 47) / 2, "Enter your username to login or create a new account");
    
    // Username field with box
    mvwprintw(form_win, 6, 5, "Username:");
    
    // Draw input box instead of underline - make it wider
    WINDOW* input_win = derwin(form_win, 3, 40, 5, 15);
    box(input_win, 0, 0);
    
    // Instructions at the bottom
    mvwprintw(form_win, form_height - 2, (form_width - 36) / 2, "Press ENTER to continue or ESC to exit");
    
    // Refresh both windows
    wrefresh(form_win);
    wrefresh(input_win);
    
    // Direct terminal input without forms
    char username[31] = {0}; // 30 chars + null terminator
    int pos = 0;
    int ch;
    bool result = false;
    
    // Position cursor at start of input field inside the input box (accounting for border)
    wmove(input_win, 1, 1);
    curs_set(1); // Make cursor visible
    keypad(input_win, TRUE); // Enable special keys
    echo(); // Show typing
    wrefresh(input_win);
    
    // Input loop
    while (true) {
        ch = wgetch(input_win);
        
        if (ch == 27) { // Escape key
            delwin(input_win);
            delwin(form_win);
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
                // Show error in red in the form window
                if (has_colors()) {
                    wattron(form_win, COLOR_PAIR(3)); // Red text for error
                }
                mvwprintw(form_win, 8, (form_width - 45) / 2, "Username cannot be empty. Please enter a username.");
                if (has_colors()) {
                    wattroff(form_win, COLOR_PAIR(3));
                }
                wrefresh(form_win);
                
                // Move cursor back to input position
                wmove(input_win, 1, 1 + pos);
                wrefresh(input_win);
                continue;
            }
            
            // Show checking message in the form window
            mvwprintw(form_win, 8, (form_width - 20) / 2, "Checking username...");
            wrefresh(form_win);
            
            // Send USER command to check if user exists
            std::string user_response = send_command_and_get_response("USER " + username_str);
            
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
            
            // bool is_existing_user = !is_new_user; // Uncomment if needed
            
            // We can remove the debug info in the final version
            // Now just clean up windows and proceed to the appropriate form
            
            // Clean up the windows before proceeding
            delwin(input_win);
            delwin(form_win);
            
            // Show password form with correct user type
            result = password_form(username_str, is_new_user);
            return result;
        }
        else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
            if (pos > 0) {
                pos--;
                // Move cursor back and replace with space
                wmove(input_win, 1, 1 + pos);
                waddch(input_win, ' ');
                // Position cursor at the correct spot
                wmove(input_win, 1, 1 + pos);
                wrefresh(input_win);
            }
        }
        else if (pos < 38 && ch >= 32 && ch <= 126) { // Printable characters - increased limit for wider boxes
            // Store character and display it
            username[pos] = ch;
            wmove(input_win, 1, 1 + pos);
            waddch(input_win, ch);
            pos++;
            wmove(input_win, 1, 1 + pos); // Move cursor to next position
            wrefresh(input_win);
        }
    }
    
    return result;
}

// Password form - second screen (handles both new and existing users)
bool password_form(const std::string& username, bool is_new_user) {
    // Clear screen completely
    clear();
    refresh();
    
    // Get screen dimensions
    int height, width;
    getmaxyx(stdscr, height, width);
    
    // Create a main border
    box(stdscr, 0, 0);
    refresh();
    
    // Calculate centered positions - make the form wider and taller
    int form_width = 70;  // Increased width
    int form_height = is_new_user ? 18 : 14; // Increased height
    int start_x = (width - form_width) / 2;
    int start_y = (height - form_height) / 2;
    
    // Create centered form window with border
    WINDOW* form_win = newwin(form_height, form_width, start_y, start_x);
    box(form_win, 0, 0);
    
    // Print title using bold centered text
    wattron(form_win, A_BOLD);
    mvwprintw(form_win, 0, (form_width - 19) / 2, " GAME RENTAL SYSTEM ");
    wattroff(form_win, A_BOLD);
    
    // User status with better messages for new users
    wattron(form_win, A_BOLD);
    if (is_new_user) {
        mvwprintw(form_win, 2, (form_width - 16) / 2, "CREATE NEW ACCOUNT");
        mvwprintw(form_win, 3, (form_width - 45) / 2, "Welcome, %s! You're creating a new account.", username.c_str());
    } else {
        mvwprintw(form_win, 2, (form_width - 10) / 2, "USER LOGIN");
        mvwprintw(form_win, 3, (form_width - 45) / 2, "Welcome back, %s! Please enter your password.", username.c_str());
    }
    wattroff(form_win, A_BOLD);
    
    // Instructions with more details - centered
    if (is_new_user) {
        mvwprintw(form_win, 5, (form_width - 43) / 2, "Please choose a password for your new account");
        mvwprintw(form_win, 6, (form_width - 40) / 2, "(You'll need to enter it twice for verification)");
    } else {
        mvwprintw(form_win, 5, (form_width - 33) / 2, "Please enter your password to log in");
    }
    
    // Password field with box
    mvwprintw(form_win, 8, 5, "Password:");
    
    // Draw input box instead of underline - make it wider
    WINDOW* pass_win = derwin(form_win, 3, 40, 7, 15);
    box(pass_win, 0, 0);
    
    // Confirm password field for new users
    WINDOW* confirm_win = NULL;
    if (is_new_user) {
        mvwprintw(form_win, 11, 5, "Confirm:");
        
        // Draw input box for confirm password - make it wider
        confirm_win = derwin(form_win, 3, 40, 10, 15);
        box(confirm_win, 0, 0);
    }
    
    // Instructions at the bottom - centered
    if (is_new_user) {
        mvwprintw(form_win, form_height - 2, (form_width - 43) / 2, "Press ENTER to create account or ESC to go back");
    } else {
        mvwprintw(form_win, form_height - 2, (form_width - 36) / 2, "Press ENTER to login or ESC to go back");
    }
    
    // Refresh all windows
    wrefresh(form_win);
    wrefresh(pass_win);
    if (is_new_user && confirm_win) {
        wrefresh(confirm_win);
    }
    
    // Direct input for password
    char password[31] = {0}; // 30 chars + null terminator
    char confirm[31] = {0};  // For new users
    int pos = 0;
    int ch;
    
    // Position cursor at start of password field inside the input box
    wmove(pass_win, 1, 1);
    curs_set(1); // Make cursor visible
    keypad(pass_win, TRUE); // Enable special keys
    noecho(); // Don't show password characters
    wrefresh(pass_win);
    
    // Input loop for password
    while (true) {
        ch = wgetch(pass_win);
        
        if (ch == 27) { // Escape key
            delwin(pass_win);
            if (is_new_user && confirm_win) {
                delwin(confirm_win);
            }
            delwin(form_win);
            return false;
        }
        else if (ch == 10) { // Enter key
            password[pos] = '\0'; // Ensure null termination
            
            if (pos == 0) {
                // Empty password - show error in red
                if (has_colors()) {
                    wattron(form_win, COLOR_PAIR(3)); // Red text for error
                }
                mvwprintw(form_win, is_new_user ? 13 : 10, (form_width - 47) / 2, "Password cannot be empty. Please enter a password.");
                if (has_colors()) {
                    wattroff(form_win, COLOR_PAIR(3));
                }
                wrefresh(form_win);
                
                // Move cursor back to password field
                wmove(pass_win, 1, 1);
                wrefresh(pass_win);
                continue;
            }
            
            if (is_new_user) {
                // Now get confirmation password
                pos = 0;
                
                // Clear any previous error message
                mvwprintw(form_win, 13, 2, "                                                      ");
                wrefresh(form_win);
                
                // Move to confirmation field
                wmove(confirm_win, 1, 1);
                wrefresh(confirm_win);
                
                // Input loop for confirm password
                while (true) {
                    ch = wgetch(confirm_win);
                    
                    if (ch == 27) { // Escape key
                        delwin(pass_win);
                        delwin(confirm_win);
                        delwin(form_win);
                        return false;
                    }
                    else if (ch == 10) { // Enter key
                        confirm[pos] = '\0'; // Ensure null termination
                        break;
                    }
                    else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
                        if (pos > 0) {
                            pos--;
                            // Replace with space
                            wmove(confirm_win, 1, 1 + pos);
                            waddch(confirm_win, ' ');
                            // Position cursor correctly
                            wmove(confirm_win, 1, 1 + pos);
                            wrefresh(confirm_win);
                        }
                    }
                    else if (pos < 38 && ch >= 32 && ch <= 126) { // Printable characters - increased limit for wider boxes
                        confirm[pos] = ch;
                        // Show asterisk instead of character
                        wmove(confirm_win, 1, 1 + pos);
                        waddch(confirm_win, '*');
                        pos++;
                        wmove(confirm_win, 1, 1 + pos);
                        wrefresh(confirm_win);
                    }
                }
                
                // Check if passwords match
                if (strcmp(password, confirm) != 0) {
                    // Show error in red
                    if (has_colors()) {
                        wattron(form_win, COLOR_PAIR(3)); // Red text for error
                    }
                    mvwprintw(form_win, 13, (form_width - 40) / 2, "Passwords do not match. Please try again.");
                    if (has_colors()) {
                        wattroff(form_win, COLOR_PAIR(3));
                    }
                    wrefresh(form_win);
                    
                    // Clear password fields
                    werase(pass_win);
                    box(pass_win, 0, 0);
                    wrefresh(pass_win);
                    
                    werase(confirm_win);
                    box(confirm_win, 0, 0);
                    wrefresh(confirm_win);
                    
                    // Reset position and move to first password field
                    pos = 0;
                    wmove(pass_win, 1, 1);
                    wrefresh(pass_win);
                    continue;
                }
                
                // Show processing message in a centered box
                // First clean up password input windows
                delwin(pass_win);
                delwin(confirm_win);
                delwin(form_win);
                
                // Create new message box
                WINDOW* msg_win = newwin(7, 40, (height - 7) / 2, (width - 40) / 2);
                box(msg_win, 0, 0);
                wattron(msg_win, A_BOLD);
                mvwprintw(msg_win, 0, (40 - 14) / 2, " Processing ");
                wattroff(msg_win, A_BOLD);
                
                mvwprintw(msg_win, 3, (40 - 25) / 2, "Creating your new account...");
                wrefresh(msg_win);
                
                // For account creation, we just use USER and PASS
                // The server detects new users automatically and handles it
                
                // Send USER command to initiate authentication
                std::string user_cmd_response = send_command_and_get_response("USER " + username);
                
                // Check if the USER command was successful
                if (user_cmd_response.find("331") == std::string::npos) {
                    mvprintw(12, 10, "Failed to initiate account creation: %s", user_cmd_response.c_str());
                    mvprintw(14, 10, "Press any key to continue...");
                    refresh();
                    getch();
                    return false;
                }
                
                // Send PASS command to set the password
                std::string pass_response = send_command_and_get_response("PASS " + std::string(password));
                
                // Check if password was set successfully
                if (pass_response.find("230") != std::string::npos) {
                    // Clean up the message window
                    delwin(msg_win);
                    
                    // Create a full-screen loading screen with animation
                    clear();
                    refresh();
                    
                    // Show success message and loading animation
                    attron(A_BOLD);
                    if (has_colors()) {
                        attron(COLOR_PAIR(2)); // Green for success
                    }
                    mvprintw(height/4, (width - 26) / 2, "ACCOUNT CREATED SUCCESSFULLY!");
                    if (has_colors()) {
                        attroff(COLOR_PAIR(2));
                    }
                    attroff(A_BOLD);
                    
                    mvprintw(height/4 + 2, (width - 32) / 2, "Welcome to the Game Rental System!");
                    
                    // Add more descriptive loading message
                    attron(A_BOLD);
                    mvprintw(height/2 - 2, (width - 21) / 2, "LOGGING IN USER: %s", username.c_str());
                    attroff(A_BOLD);
                    
                    // Create loading animation
                    mvprintw(height/2, (width - 19) / 2, "Loading main menu...");
                    
                    // Progress bar box
                    WINDOW* progress_win = newwin(3, 52, height/2 + 2, (width - 52) / 2);
                    box(progress_win, 0, 0);
                    wrefresh(progress_win);
                    
                    // Animate the loading bar
                    for (int i = 0; i < 50; i++) {
                        mvwaddch(progress_win, 1, i + 1, ACS_BLOCK);
                        wrefresh(progress_win);
                        napms(30); // Short delay for animation
                    }
                    
                    // Clean up
                    delwin(progress_win);
                    
                    is_authenticated = true;
                    current_user = username;
                    return true;
                } else {
                    // Clean up the message window
                    delwin(msg_win);
                    
                    // Create an error message box
                    WINDOW* error_win = newwin(10, 60, (height - 10) / 2, (width - 60) / 2);
                    box(error_win, 0, 0);
                    
                    // Add title with error colors
                    wattron(error_win, A_BOLD);
                    if (has_colors()) {
                        wattron(error_win, COLOR_PAIR(3)); // Red for error
                    }
                    mvwprintw(error_win, 0, (60 - 16) / 2, " ERROR ");
                    if (has_colors()) {
                        wattroff(error_win, COLOR_PAIR(3));
                    }
                    wattroff(error_win, A_BOLD);
                    
                    // Error message - word wrap if needed
                    std::string error_msg = "Account creation failed: " + pass_response;
                    if (error_msg.length() > 50) {
                        mvwprintw(error_win, 3, 5, "%s", error_msg.substr(0, 50).c_str());
                        mvwprintw(error_win, 4, 5, "%s", error_msg.substr(50).c_str());
                    } else {
                        mvwprintw(error_win, 3, (60 - error_msg.length()) / 2, "%s", error_msg.c_str());
                    }
                    
                    mvwprintw(error_win, 8, (60 - 26) / 2, "Press any key to continue...");
                    
                    wrefresh(error_win);
                    wgetch(error_win);
                    delwin(error_win);
                    return false;
                }
            } else {
                // Send PASS command with password
                std::string pass_response = send_command_and_get_response("PASS " + std::string(password));
                
                // Check if login was successful
                if (pass_response.find("230") != std::string::npos) {
                    // Clean up existing windows
                    delwin(pass_win);
                    delwin(form_win);
                    
                    // Create a full-screen loading screen with animation
                    clear();
                    refresh();
                    
                    // Show success message and loading animation
                    attron(A_BOLD);
                    if (has_colors()) {
                        attron(COLOR_PAIR(2)); // Green for success
                    }
                    mvprintw(height/4, (width - 16) / 2, "LOGIN SUCCESSFUL!");
                    if (has_colors()) {
                        attroff(COLOR_PAIR(2));
                    }
                    attroff(A_BOLD);
                    
                    mvprintw(height/4 + 2, (width - 37) / 2, "Welcome back to the Game Rental System!");
                    
                    // Add more descriptive loading message
                    attron(A_BOLD);
                    mvprintw(height/2 - 2, (width - 21) / 2, "LOGGING IN USER: %s", username.c_str());
                    attroff(A_BOLD);
                    
                    // Create loading animation
                    mvprintw(height/2, (width - 19) / 2, "Loading main menu...");
                    
                    // Progress bar box
                    WINDOW* progress_win = newwin(3, 52, height/2 + 2, (width - 52) / 2);
                    box(progress_win, 0, 0);
                    wrefresh(progress_win);
                    
                    // Animate the loading bar
                    for (int i = 0; i < 50; i++) {
                        mvwaddch(progress_win, 1, i + 1, ACS_BLOCK);
                        wrefresh(progress_win);
                        napms(30); // Short delay for animation
                    }
                    
                    // Clean up
                    delwin(progress_win);
                    
                    is_authenticated = true;
                    current_user = username;
                    return true;
                } else {
                    // Password is incorrect - clear field and show red error message
                    
                    // Clear password field
                    werase(pass_win);
                    box(pass_win, 0, 0);
                    wrefresh(pass_win);
                    pos = 0; // Reset cursor position
                    
                    // Show error in red in a designated area
                    if (has_colors()) {
                        wattron(form_win, COLOR_PAIR(3)); // Red text for error
                    }
                    // Clear any previous message first
                    for (int i = 0; i < form_width - 10; i++) {
                        mvwaddch(form_win, form_height - 5, 5 + i, ' ');
                    }
                    // Then add the new message centered
                    mvwprintw(form_win, form_height - 5, (form_width - 36) / 2, "Incorrect password. Please try again.");
                    if (has_colors()) {
                        wattroff(form_win, COLOR_PAIR(3));
                    }
                    wrefresh(form_win);
                    
                    // Move cursor back to password field
                    wmove(pass_win, 1, 1);
                    wrefresh(pass_win);
                    
                    // Continue the input loop (return to password entry)
                    continue;
                }
            }
        }
        else if (ch == KEY_BACKSPACE || ch == 127) { // Backspace
            if (pos > 0) {
                pos--;
                // Replace with space
                wmove(pass_win, 1, 1 + pos);
                waddch(pass_win, ' ');
                // Position cursor correctly
                wmove(pass_win, 1, 1 + pos);
                wrefresh(pass_win);
            }
        }
        else if (pos < 38 && ch >= 32 && ch <= 126) { // Printable characters - increased limit for wider boxes
            password[pos] = ch;
            // Show asterisk instead of character
            wmove(pass_win, 1, 1 + pos);
            waddch(pass_win, '*');
            pos++;
            wmove(pass_win, 1, 1 + pos);
            wrefresh(pass_win);
        }
    }
    
    return false;
}

// Command interface - enhanced version
void command_interface() {
    clear();
    
    // Get screen dimensions
    int height, width;
    getmaxyx(stdscr, height, width);
    
    // Create a styled window layout with box drawing characters
    box(stdscr, 0, 0);
    
    // Create a header with color background if colors available
    if (has_colors()) {
        attron(COLOR_PAIR(1)); // White on blue for header
    }
    for (int i = 0; i < width; i++) {
        mvaddch(0, i, ' ');
    }
    
    // Draw title in the header
    attron(A_BOLD);
    mvprintw(0, (width - 31) / 2, "GAME RENTAL SYSTEM");
    attroff(A_BOLD);
    
    if (has_colors()) {
        attroff(COLOR_PAIR(1));
    }
    
    // Draw user info with a box
    WINDOW* user_info = newwin(3, width - 4, 2, 2);
    box(user_info, 0, 0);
    mvwprintw(user_info, 0, 2, " User Info ");
    mvwprintw(user_info, 1, 2, "Logged in as: %s", current_user.c_str());
    wrefresh(user_info);
    
    // Instructions panel
    WINDOW* instructions = newwin(3, width - 4, 6, 2);
    box(instructions, 0, 0);
    mvwprintw(instructions, 0, 2, " Help ");
    mvwprintw(instructions, 1, 2, "Type commands and press Enter. Type 'HELP' for list of commands. Type 'EXIT' to log out.");
    wrefresh(instructions);
    
    // Create command output area
    WINDOW* output_win = newwin(height - 14, width - 4, 10, 2);
    box(output_win, 0, 0);
    mvwprintw(output_win, 0, 2, " Command Output ");
    wrefresh(output_win);
    
    // Create scrolling pad for command output
    // Pad needs to be larger than visible area to allow scrolling
    WINDOW* output_pad = newpad(500, width - 6); // 500 lines should be enough for most outputs
    
    // Current position in the output pad
    int pad_pos = 0;
    
    // Display help at start
    std::string help_response = send_command_and_get_response("HELP");
    wattron(output_pad, A_BOLD);
    mvwprintw(output_pad, pad_pos++, 0, "Available commands:");
    wattroff(output_pad, A_BOLD);
    
    std::istringstream help_stream(help_response);
    std::string line;
    while (std::getline(help_stream, line)) {
        mvwprintw(output_pad, pad_pos++, 2, "%s", line.c_str());
    }
    
    // Show the pad content in the visible area
    prefresh(output_pad, 0, 0, 11, 3, height - 5, width - 5);
    
    pad_pos += 1; // Add an extra blank line
    
    // Create a command input bar at the bottom
    WINDOW* cmd_win = newwin(3, width - 4, height - 4, 2);
    box(cmd_win, 0, 0);
    mvwprintw(cmd_win, 0, 2, " Enter Command ");
    wrefresh(cmd_win);
    
    // Command input loop
    while (true) {
        // Draw Command prompt
        wmove(cmd_win, 1, 2);
        wclrtoeol(cmd_win); // Clear previous command
        
        // Use green for the # prompt
        wattron(cmd_win, A_BOLD);
        if (has_colors()) {
            wattron(cmd_win, COLOR_PAIR(2)); // Green for hash
        }
        mvwprintw(cmd_win, 1, 2, "#");
        if (has_colors()) {
            wattroff(cmd_win, COLOR_PAIR(2));
        }
        
        // Space after the hash
        mvwprintw(cmd_win, 1, 3, " ");
        wattroff(cmd_win, A_BOLD);
        wrefresh(cmd_win);
        
        // Make cursor visible and position it for input
        curs_set(1);
        
        // Get user input
        char cmd_buf[256] = {0};
        echo(); // Show typing
        mvwgetnstr(cmd_win, 1, 4, cmd_buf, 255);
        noecho(); // Hide typing for next iteration
        
        std::string command(cmd_buf);
        
        // Handle exit
        if (command == "EXIT" || command == "exit") {
            // Create a nice goodbye animation
            clear();
            box(stdscr, 0, 0);
            
            attron(A_BOLD);
            mvprintw(height/2 - 2, (width - 20) / 2, "Logging out...");
            attroff(A_BOLD);
            
            // Countdown animation
            for (int i = 3; i > 0; i--) {
                mvprintw(height/2, (width - 10) / 2, "Goodbye in %d", i);
                refresh();
                napms(400);
            }
            
            mvprintw(height/2, (width - 20) / 2, "Goodbye! Thank you!");
            refresh();
            napms(700);
            break;
        }
        
        // Skip empty commands
        if (command.empty()) {
            continue;
        }
        
        // Show command in output with some styling
        wattron(output_pad, A_BOLD);
        
        // Use green specifically for the # character
        if (has_colors()) {
            wattron(output_pad, COLOR_PAIR(2)); // Green for prompt character
        }
        mvwprintw(output_pad, pad_pos, 0, "#");
        if (has_colors()) {
            wattroff(output_pad, COLOR_PAIR(2));
            
            // Use yellow for the command text
            wattron(output_pad, COLOR_PAIR(4)); 
        }
        
        // Print the actual command after the prompt
        mvwprintw(output_pad, pad_pos++, 2, "%s", command.c_str());
        
        if (has_colors()) {
            wattroff(output_pad, COLOR_PAIR(4));
        }
        wattroff(output_pad, A_BOLD);
        
        // Process command
        std::string response = send_command_and_get_response(command);
        
        // Display response with wrapping if needed
        std::istringstream iss(response);
        std::string resp_line;
        while (std::getline(iss, resp_line)) {
            // Handle long lines with wrap
            int max_width = width - 10; // Leave some room from edges
            if ((int)resp_line.length() > max_width) {
                for (size_t i = 0; i < resp_line.length(); i += max_width) {
                    mvwprintw(output_pad, pad_pos++, 2, "%s", 
                             resp_line.substr(i, std::min((size_t)max_width, resp_line.length() - i)).c_str());
                }
            } else {
                mvwprintw(output_pad, pad_pos++, 2, "%s", resp_line.c_str());
            }
        }
        
        // Add a blank line after response
        pad_pos++;
        
        // Calculate visible area and scroll if needed
        int visible_height = height - 16; // Height of visible output area
        int scroll_start = (pad_pos > visible_height) ? pad_pos - visible_height : 0;
        
        // Show the updated pad content
        prefresh(output_pad, scroll_start, 0, 11, 3, height - 5, width - 5);
    }
    
    // Clean up windows
    delwin(output_pad);
    delwin(output_win);
    delwin(cmd_win);
    delwin(instructions);
    delwin(user_info);
    
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