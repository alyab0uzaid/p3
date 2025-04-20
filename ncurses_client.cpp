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
                    
                    // First clear the screen completely to make sure messages are visible
                    clear();
                    refresh();
                    
                    // Draw a border
                    box(stdscr, 0, 0);
                    refresh();
                    
                    // Draw title at the top
                    attron(A_BOLD);
                    mvprintw(2, (width - 19) / 2, "GAME RENTAL SYSTEM");
                    attroff(A_BOLD);
                    
                    // Add more descriptive loading message
                    attron(A_BOLD);
                    mvprintw(height/3, (width - 21) / 2, "LOGGING IN USER: %s", username.c_str());
                    attroff(A_BOLD);
                    
                    // Create loading animation
                    if (has_colors()) {
                        attron(COLOR_PAIR(2)); // Green text for success message
                    }
                    attron(A_BOLD | A_BLINK); // Add blinking effect
                    mvprintw(height/3 + 2, (width - 34) / 2, "SUCCESS! LOGGING IN TO SYSTEM...");
                    attroff(A_BOLD | A_BLINK);
                    if (has_colors()) {
                        attroff(COLOR_PAIR(2));
                    }
                    
                    // Force refresh to make sure messages are displayed
                    refresh();
                    
                    // Progress bar box - positioned lower to avoid overlap
                    WINDOW* progress_win = newwin(3, 52, height/3 + 5, (width - 52) / 2);
                    box(progress_win, 0, 0);
                    wrefresh(progress_win);
                    
                    // Animate the loading bar with green hashes
                    if (has_colors()) {
                        wattron(progress_win, COLOR_PAIR(2)); // Green for hash characters
                    }
                    for (int i = 0; i < 50; i++) {
                        mvwaddch(progress_win, 1, i + 1, '#'); // Use hash character instead of block
                        wrefresh(progress_win);
                        napms(30); // Short delay for animation
                    }
                    if (has_colors()) {
                        wattroff(progress_win, COLOR_PAIR(2));
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
                    
                    // First clear the screen completely to make sure messages are visible
                    clear();
                    refresh();
                    
                    // Draw a border
                    box(stdscr, 0, 0);
                    refresh();
                    
                    // Draw title at the top
                    attron(A_BOLD);
                    mvprintw(2, (width - 19) / 2, "GAME RENTAL SYSTEM");
                    attroff(A_BOLD);
                    
                    // Add more descriptive loading message
                    attron(A_BOLD);
                    mvprintw(height/3, (width - 21) / 2, "LOGGING IN USER: %s", username.c_str());
                    attroff(A_BOLD);
                    
                    // Create loading animation
                    if (has_colors()) {
                        attron(COLOR_PAIR(2)); // Green text for success message
                    }
                    attron(A_BOLD | A_BLINK); // Add blinking effect
                    mvprintw(height/3 + 2, (width - 34) / 2, "SUCCESS! LOGGING IN TO SYSTEM...");
                    attroff(A_BOLD | A_BLINK);
                    if (has_colors()) {
                        attroff(COLOR_PAIR(2));
                    }
                    
                    // Force refresh to make sure messages are displayed
                    refresh();
                    
                    // Progress bar box - positioned lower to avoid overlap
                    WINDOW* progress_win = newwin(3, 52, height/3 + 5, (width - 52) / 2);
                    box(progress_win, 0, 0);
                    wrefresh(progress_win);
                    
                    // Animate the loading bar with green hashes
                    if (has_colors()) {
                        wattron(progress_win, COLOR_PAIR(2)); // Green for hash characters
                    }
                    for (int i = 0; i < 50; i++) {
                        mvwaddch(progress_win, 1, i + 1, '#'); // Use hash character instead of block
                        wrefresh(progress_win);
                        napms(30); // Short delay for animation
                    }
                    if (has_colors()) {
                        wattroff(progress_win, COLOR_PAIR(2));
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

// Interactive menu-based interface with nested menus
void command_interface() {
    // Get screen dimensions
    int height, width;
    getmaxyx(stdscr, height, width);
    
    // Define menu levels
    enum MenuLevel {
        MAIN_MENU,
        BROWSE_MENU,
        RENT_MENU,
        MYGAMES_MENU,
        GAME_DETAILS,
        SEARCH_RESULTS,
        HISTORY_DISPLAY,
        RECOMMEND_DISPLAY
    };
    
    // Define main menu options
    const int NUM_MAIN_MENU_ITEMS = 7;
    const char* main_menu_items[NUM_MAIN_MENU_ITEMS] = {
        "Browse Games",
        "Rent a Game",
        "My Games",
        "Search Games",
        "View History",
        "Get Recommendations",
        "Log Out"
    };
    
    // Define browse submenu options
    const int NUM_BROWSE_ITEMS = 4;
    const char* browse_menu_items[NUM_BROWSE_ITEMS] = {
        "List All Games",
        "List by Genre",
        "List by Platform",
        "Back to Main Menu"
    };
    
    // Define rent submenu options
    const int NUM_RENT_ITEMS = 3;
    const char* rent_menu_items[NUM_RENT_ITEMS] = {
        "Checkout Game",
        "Return Game",
        "Back to Main Menu"
    };
    
    // Define my games submenu options
    const int NUM_MYGAMES_ITEMS = 4;
    const char* mygames_menu_items[NUM_MYGAMES_ITEMS] = {
        "Currently Rented Games",
        "Rate a Game",
        "View Recommendations",
        "Back to Main Menu"
    };
    
    // Initialize menu state
    MenuLevel current_level = MAIN_MENU;
    int main_selection = 0;
    int submenu_selection = 0;
    std::string response_text = "";
    std::string search_query = "";
    std::string selected_game = "";
    std::string selected_genre = "";
    std::string selected_platform = "";
    std::vector<std::string> game_list;
    int list_selection = 0;
    
    // Main menu loop
    while (true) {
        // Clear screen and create basic layout
        clear();
        
        // Create a header with color background
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
        
        // Create content area
        box(stdscr, 0, 0);
        
        // User info
        attron(A_BOLD);
        mvprintw(2, 2, "User: %s", current_user.c_str());
        attroff(A_BOLD);
        
        // Horizontal separator
        for (int i = 1; i < width - 1; i++) {
            mvaddch(3, i, ACS_HLINE);
        }
        
        // Display the appropriate menu based on current level
        switch (current_level) {
            case MAIN_MENU: {
                // Main menu title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - 9) / 2, "MAIN MENU");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Display menu items
                for (int i = 0; i < NUM_MAIN_MENU_ITEMS; i++) {
                    // Highlight current selection
                    if (i == main_selection) {
                        attron(A_REVERSE);
                        if (has_colors()) {
                            attron(COLOR_PAIR(2)); // Green highlight
                        }
                    }
                    
                    // Center the menu item
                    mvprintw(7 + i, (width - strlen(main_menu_items[i])) / 2, "%s", main_menu_items[i]);
                    
                    if (i == main_selection) {
                        attroff(A_REVERSE);
                        if (has_colors()) {
                            attroff(COLOR_PAIR(2));
                        }
                    }
                }
                
                // Instructions
                mvprintw(height - 3, 2, "Use UP/DOWN to navigate, ENTER to select, Q to quit");
                break;
            }
                
            case BROWSE_MENU: {
                // Browse menu title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - 12) / 2, "BROWSE GAMES");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Display browse submenu
                for (int i = 0; i < NUM_BROWSE_ITEMS; i++) {
                    // Highlight current selection
                    if (i == submenu_selection) {
                        attron(A_REVERSE);
                        if (has_colors()) {
                            attron(COLOR_PAIR(2)); // Green highlight
                        }
                    }
                    
                    // Center the menu item
                    mvprintw(7 + i, (width - strlen(browse_menu_items[i])) / 2, "%s", browse_menu_items[i]);
                    
                    if (i == submenu_selection) {
                        attroff(A_REVERSE);
                        if (has_colors()) {
                            attroff(COLOR_PAIR(2));
                        }
                    }
                }
                
                // Instructions
                mvprintw(height - 3, 2, "Use UP/DOWN to navigate, ENTER to select, ESC to go back");
                break;
            }
                
            case RENT_MENU: {
                // Rent menu title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - 16) / 2, "RENT/RETURN GAMES");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Display rent submenu
                for (int i = 0; i < NUM_RENT_ITEMS; i++) {
                    // Highlight current selection
                    if (i == submenu_selection) {
                        attron(A_REVERSE);
                        if (has_colors()) {
                            attron(COLOR_PAIR(2)); // Green highlight
                        }
                    }
                    
                    // Center the menu item
                    mvprintw(7 + i, (width - strlen(rent_menu_items[i])) / 2, "%s", rent_menu_items[i]);
                    
                    if (i == submenu_selection) {
                        attroff(A_REVERSE);
                        if (has_colors()) {
                            attroff(COLOR_PAIR(2));
                        }
                    }
                }
                
                // Instructions
                mvprintw(height - 3, 2, "Use UP/DOWN to navigate, ENTER to select, ESC to go back");
                break;
            }
                
            case MYGAMES_MENU: {
                // My Games menu title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - 8) / 2, "MY GAMES");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Display my games submenu
                for (int i = 0; i < NUM_MYGAMES_ITEMS; i++) {
                    // Highlight current selection
                    if (i == submenu_selection) {
                        attron(A_REVERSE);
                        if (has_colors()) {
                            attron(COLOR_PAIR(2)); // Green highlight
                        }
                    }
                    
                    // Center the menu item
                    mvprintw(7 + i, (width - strlen(mygames_menu_items[i])) / 2, "%s", mygames_menu_items[i]);
                    
                    if (i == submenu_selection) {
                        attroff(A_REVERSE);
                        if (has_colors()) {
                            attroff(COLOR_PAIR(2));
                        }
                    }
                }
                
                // Instructions
                mvprintw(height - 3, 2, "Use UP/DOWN to navigate, ENTER to select, ESC to go back");
                break;
            }
                
            case GAME_DETAILS: {
                // Game details title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - 12) / 2, "GAME DETAILS");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Create a content area for game details
                WINDOW* details_win = newwin(height - 10, width - 8, 7, 4);
                box(details_win, 0, 0);
                
                // Display game details
                if (!selected_game.empty()) {
                    wattron(details_win, A_BOLD);
                    mvwprintw(details_win, 1, 2, "Selected Game: %s", selected_game.c_str());
                    wattroff(details_win, A_BOLD);
                    
                    // Get game details from server
                    std::string details = send_command_and_get_response("SHOW " + selected_game);
                    
                    // Parse and display details nicely
                    int line = 3;
                    std::istringstream iss(details);
                    std::string detail_line;
                    while (std::getline(iss, detail_line) && line < height - 14) {
                        // Format each line with a bullet point
                        if (!detail_line.empty() && detail_line[0] != '-') {
                            detail_line = "• " + detail_line;
                        }
                        mvwprintw(details_win, line++, 2, "%s", detail_line.c_str());
                    }
                    
                    // Add action buttons
                    wattron(details_win, A_BOLD);
                    mvwprintw(details_win, height - 16, (width - 40) / 2, "Press R to rent this game, ESC to go back");
                    wattroff(details_win, A_BOLD);
                }
                
                wrefresh(details_win);
                
                // Instructions
                mvprintw(height - 3, 2, "Press ESC to go back, R to rent this game");
                
                // Clean up
                delwin(details_win);
                break;
            }
                
            case SEARCH_RESULTS: {
                // Search results title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - 13) / 2, "SEARCH RESULTS");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Show search query
                mvprintw(6, 4, "Search Query: %s", search_query.c_str());
                
                // Split the screen: left side for raw response, right side for selectable list
                int left_width = width * 0.65;
                
                // Left side - Raw server response
                WINDOW* raw_win = newwin(height - 12, left_width, 8, 4);
                box(raw_win, 0, 0);
                wattron(raw_win, A_BOLD);
                mvwprintw(raw_win, 0, 2, " Server Response ");
                wattroff(raw_win, A_BOLD);
                
                // Display raw response
                int line = 1;
                std::istringstream iss_raw(response_text);
                std::string raw_line;
                while (std::getline(iss_raw, raw_line) && line < height - 14) {
                    mvwprintw(raw_win, line++, 2, "%s", raw_line.c_str());
                }
                wrefresh(raw_win);
                
                // Right side - Selectable game list (if any games were parsed)
                if (!game_list.empty()) {
                    WINDOW* list_win = newwin(height - 12, width - left_width - 8, 8, 4 + left_width);
                    box(list_win, 0, 0);
                    wattron(list_win, A_BOLD);
                    mvwprintw(list_win, 0, 2, " Game List ");
                    wattroff(list_win, A_BOLD);
                    
                    // Calculate visible items and scrolling
                    int max_visible = height - 14;
                    int start_idx = (list_selection / max_visible) * max_visible;
                    int end_idx = std::min(start_idx + max_visible, (int)game_list.size());
                    
                    for (int i = start_idx; i < end_idx; i++) {
                        // Highlight current selection
                        if (i == list_selection) {
                            wattron(list_win, A_REVERSE);
                            if (has_colors()) {
                                wattron(list_win, COLOR_PAIR(2)); // Green highlight
                            }
                        }
                        
                        // Truncate if needed to fit in window
                        std::string game_name = game_list[i];
                        if (game_name.length() > (unsigned)(width - left_width - 12)) {
                            game_name = game_name.substr(0, width - left_width - 15) + "...";
                        }
                        
                        mvwprintw(list_win, i - start_idx + 1, 2, "%s", game_name.c_str());
                        
                        if (i == list_selection) {
                            wattroff(list_win, A_REVERSE);
                            if (has_colors()) {
                                wattroff(list_win, COLOR_PAIR(2));
                            }
                        }
                    }
                    wrefresh(list_win);
                    delwin(list_win);
                }
                
                // Instructions
                mvprintw(height - 3, 2, "Use UP/DOWN to navigate, ENTER to view details, ESC to go back");
                
                // Clean up
                delwin(raw_win);
                break;
            }
                
            case HISTORY_DISPLAY:
            case RECOMMEND_DISPLAY: {
                // Results title
                attron(A_BOLD);
                if (has_colors()) {
                    attron(COLOR_PAIR(4)); // Yellow for title
                }
                mvprintw(5, (width - (current_level == HISTORY_DISPLAY ? 13 : 18)) / 2, 
                         current_level == HISTORY_DISPLAY ? "RENTAL HISTORY" : "RECOMMENDATIONS");
                if (has_colors()) {
                    attroff(COLOR_PAIR(4));
                }
                attroff(A_BOLD);
                
                // Create a content area for results with a title
                WINDOW* results_win = newwin(height - 10, width - 8, 7, 4);
                box(results_win, 0, 0);
                
                // Add a title to the window
                wattron(results_win, A_BOLD);
                mvwprintw(results_win, 0, 2, " Server Response ");
                wattroff(results_win, A_BOLD);
                
                // Display results with better formatting
                int line = 1;
                std::istringstream iss(response_text);
                std::string resp_line;
                
                // Skip the first line if it's just a status code
                if (std::getline(iss, resp_line) && resp_line.length() >= 3 && 
                    isdigit(resp_line[0]) && isdigit(resp_line[1]) && isdigit(resp_line[2])) {
                    // Display it with some formatting
                    wattron(results_win, A_BOLD);
                    if (has_colors()) {
                        wattron(results_win, COLOR_PAIR(2)); // Green for status
                    }
                    mvwprintw(results_win, line++, 2, "Status: %s", resp_line.c_str());
                    if (has_colors()) {
                        wattroff(results_win, COLOR_PAIR(2));
                    }
                    wattroff(results_win, A_BOLD);
                    
                    // Add a blank line for separation
                    line++;
                } else {
                    // If we didn't find a status code, reset and show everything
                    iss.clear();
                    iss.seekg(0, std::ios::beg);
                }
                
                // Display the rest of the content
                while (std::getline(iss, resp_line) && line < height - 12) {
                    // Add bullet points to entries that look like data
                    if (!resp_line.empty() && resp_line[0] != '-' && 
                        resp_line[0] != '2' && resp_line.find(':') == std::string::npos) {
                        if (has_colors()) {
                            wattron(results_win, COLOR_PAIR(4)); // Yellow for items
                        }
                        mvwprintw(results_win, line++, 2, "• %s", resp_line.c_str());
                        if (has_colors()) {
                            wattroff(results_win, COLOR_PAIR(4));
                        }
                    } else {
                        mvwprintw(results_win, line++, 2, "%s", resp_line.c_str());
                    }
                }
                
                wrefresh(results_win);
                
                // Instructions
                mvprintw(height - 3, 2, "Press ESC to go back to main menu");
                
                // Clean up
                delwin(results_win);
                break;
            }
        }
        
        // Refresh screen
        refresh();
        
        // Handle input
        keypad(stdscr, TRUE); // Enable arrow keys
        noecho(); // Don't show input
        curs_set(0); // Hide cursor
        
        int ch = getch();
        
        // Process input based on current menu level
        switch (current_level) {
            case MAIN_MENU:
                switch (ch) {
                    case KEY_UP:
                        main_selection = (main_selection - 1 + NUM_MAIN_MENU_ITEMS) % NUM_MAIN_MENU_ITEMS;
                        break;
                        
                    case KEY_DOWN:
                        main_selection = (main_selection + 1) % NUM_MAIN_MENU_ITEMS;
                        break;
                        
                    case 10: // Enter key
                        if (main_selection == NUM_MAIN_MENU_ITEMS - 1) { // Log Out option
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
                            return;
                        } else {
                            // Process main menu selection
                            submenu_selection = 0; // Reset submenu selection
                            
                            if (main_selection == 0) { // Browse Games
                                current_level = BROWSE_MENU;
                            }
                            else if (main_selection == 1) { // Rent a Game
                                current_level = RENT_MENU;
                            }
                            else if (main_selection == 2) { // My Games
                                current_level = MYGAMES_MENU;
                            }
                            else if (main_selection == 3) { // Search Games
                                // Show search dialog
                                clear();
                                box(stdscr, 0, 0);
                                mvprintw(height/2 - 2, (width - 20) / 2, "Search for a game:");
                                
                                // Input box
                                echo();
                                curs_set(1);
                                char search_buf[256] = {0};
                                mvprintw(height/2, (width - 30) / 2, "");
                                for (int i = 0; i < 30; i++) {
                                    mvaddch(height/2, (width - 30) / 2 + i, '_');
                                }
                                mvprintw(height/2, (width - 30) / 2, "");
                                getnstr(search_buf, 255);
                                noecho();
                                curs_set(0);
                                
                                search_query = search_buf;
                                if (!search_query.empty()) {
                                    // Execute search and parse results
                                    std::string results = send_command_and_get_response("SEARCH " + search_query);
                                    
                                    // Store full response for display
                                    response_text = results;
                                    
                                    // Parse results into game list
                                    game_list.clear();
                                    std::istringstream iss(results);
                                    std::string result_line;
                                    while (std::getline(iss, result_line)) {
                                        // Add any non-empty line that looks like a game title
                                        if (!result_line.empty() && 
                                            result_line[0] != '-' && result_line[0] != '2' && 
                                            result_line.find(':') == std::string::npos) {
                                            game_list.push_back(result_line);
                                        }
                                    }
                                    
                                    list_selection = 0;
                                    current_level = SEARCH_RESULTS;
                                }
                            }
                            else if (main_selection == 4) { // View History
                                response_text = send_command_and_get_response("HISTORY");
                                current_level = HISTORY_DISPLAY;
                            }
                            else if (main_selection == 5) { // Get Recommendations
                                response_text = send_command_and_get_response("RECOMMEND");
                                current_level = RECOMMEND_DISPLAY;
                            }
                        }
                        break;
                        
                    case 'q':
                    case 'Q':
                        // Quick exit
                        clear();
                        mvprintw(height/2, (width - 15) / 2, "Logging out...");
                        refresh();
                        napms(500);
                        return;
                }
                break;
                
            case BROWSE_MENU:
                switch (ch) {
                    case KEY_UP:
                        submenu_selection = (submenu_selection - 1 + NUM_BROWSE_ITEMS) % NUM_BROWSE_ITEMS;
                        break;
                        
                    case KEY_DOWN:
                        submenu_selection = (submenu_selection + 1) % NUM_BROWSE_ITEMS;
                        break;
                        
                    case 10: // Enter key
                        if (submenu_selection == NUM_BROWSE_ITEMS - 1) {
                            // Back to main menu
                            current_level = MAIN_MENU;
                        } else {
                            // Process browse submenu selection
                            switch (submenu_selection) {
                                case 0: // List All Games
                                    // Get game list and display as selectable list
                                    std::string results = send_command_and_get_response("LIST");
                                    
                                    // Simplified parsing - keep raw results to visualize output
                                    response_text = results;
                                    
                                    // Also parse into game list for selection
                                    game_list.clear();
                                    std::istringstream iss(results);
                                    std::string result_line;
                                    while (std::getline(iss, result_line)) {
                                        // Add any non-empty line that looks like a game title
                                        if (!result_line.empty() && !result_line.empty() && 
                                            result_line[0] != '-' && result_line[0] != '2' && 
                                            result_line.find(':') == std::string::npos) {
                                            game_list.push_back(result_line);
                                        }
                                    }
                                    
                                    // Show results screen even if parsing didn't identify games
                                    list_selection = 0;
                                    current_level = SEARCH_RESULTS;
                                    search_query = "All Games";
                                    break;
                            }
                        }
                        break;
                        
                    case 27: // ESC key
                    case 'q':
                    case 'Q':
                        current_level = MAIN_MENU;
                        break;
                }
                break;
                
            case RENT_MENU:
                switch (ch) {
                    case KEY_UP:
                        submenu_selection = (submenu_selection - 1 + NUM_RENT_ITEMS) % NUM_RENT_ITEMS;
                        break;
                        
                    case KEY_DOWN:
                        submenu_selection = (submenu_selection + 1) % NUM_RENT_ITEMS;
                        break;
                        
                    case 10: // Enter key
                        if (submenu_selection == NUM_RENT_ITEMS - 1) {
                            // Back to main menu
                            current_level = MAIN_MENU;
                        } else {
                            // Process rent submenu selection
                            switch (submenu_selection) {
                                case 0: // Checkout Game
                                    // Get list of available games first
                                    std::string results = send_command_and_get_response("LIST");
                                    
                                    // Store raw response for display
                                    response_text = results;
                                    
                                    // Parse results into game list
                                    game_list.clear();
                                    std::istringstream iss(results);
                                    std::string result_line;
                                    while (std::getline(iss, result_line)) {
                                        // Add any non-empty line that looks like a game title
                                        if (!result_line.empty() && 
                                            result_line[0] != '-' && result_line[0] != '2' && 
                                            result_line.find(':') == std::string::npos) {
                                            game_list.push_back(result_line);
                                        }
                                    }
                                    
                                    // Show results even if no games were parsed
                                    list_selection = 0;
                                    current_level = SEARCH_RESULTS;
                                    search_query = "Available Games";
                                    break;
                            }
                        }
                        break;
                        
                    case 27: // ESC key
                    case 'q':
                    case 'Q':
                        current_level = MAIN_MENU;
                        break;
                }
                break;
                
            case MYGAMES_MENU:
                switch (ch) {
                    case KEY_UP:
                        submenu_selection = (submenu_selection - 1 + NUM_MYGAMES_ITEMS) % NUM_MYGAMES_ITEMS;
                        break;
                        
                    case KEY_DOWN:
                        submenu_selection = (submenu_selection + 1) % NUM_MYGAMES_ITEMS;
                        break;
                        
                    case 10: // Enter key
                        if (submenu_selection == NUM_MYGAMES_ITEMS - 1) {
                            // Back to main menu
                            current_level = MAIN_MENU;
                        } else {
                            // Process my games submenu selection
                            switch (submenu_selection) {
                                case 0: // Currently Rented Games
                                    // Get list of rented games
                                    response_text = send_command_and_get_response("MYGAMES");
                                    current_level = HISTORY_DISPLAY; // Reuse history display for this
                                    break;
                                    
                                case 1: // Rate a Game
                                    // Get list of games to rate (previously rented)
                                    response_text = send_command_and_get_response("HISTORY");
                                    current_level = HISTORY_DISPLAY;
                                    break;
                                    
                                case 2: // View Recommendations
                                    response_text = send_command_and_get_response("RECOMMEND");
                                    current_level = RECOMMEND_DISPLAY;
                                    break;
                            }
                        }
                        break;
                        
                    case 27: // ESC key
                    case 'q':
                    case 'Q':
                        current_level = MAIN_MENU;
                        break;
                }
                break;
                
            case GAME_DETAILS:
                switch (ch) {
                    case 'r':
                    case 'R':
                        // Rent the selected game
                        if (!selected_game.empty()) {
                            std::string rent_response = send_command_and_get_response("CHECKOUT " + selected_game);
                            
                            // Show rental status in a popup
                            clear();
                            box(stdscr, 0, 0);
                            
                            if (rent_response.find("success") != std::string::npos) {
                                attron(A_BOLD);
                                if (has_colors()) {
                                    attron(COLOR_PAIR(2)); // Green for success
                                }
                                mvprintw(height/2 - 2, (width - 15) / 2, "RENTAL SUCCESS!");
                                if (has_colors()) {
                                    attroff(COLOR_PAIR(2));
                                }
                                attroff(A_BOLD);
                                
                                mvprintw(height/2, (width - 40) / 2, "You have successfully rented: %s", selected_game.c_str());
                            } else {
                                attron(A_BOLD);
                                if (has_colors()) {
                                    attron(COLOR_PAIR(3)); // Red for error
                                }
                                mvprintw(height/2 - 2, (width - 13) / 2, "RENTAL ERROR");
                                if (has_colors()) {
                                    attroff(COLOR_PAIR(3));
                                }
                                attroff(A_BOLD);
                                
                                mvprintw(height/2, (width - 40) / 2, "Could not rent: %s", rent_response.c_str());
                            }
                            
                            mvprintw(height/2 + 2, (width - 26) / 2, "Press any key to continue...");
                            refresh();
                            getch();
                            
                            // Go back to browse menu
                            current_level = BROWSE_MENU;
                        }
                        break;
                        
                    case 27: // ESC key
                    case 'q':
                    case 'Q':
                        current_level = SEARCH_RESULTS; // Go back to search results
                        break;
                }
                break;
                
            case SEARCH_RESULTS:
                switch (ch) {
                    case KEY_UP:
                        if (!game_list.empty()) {
                            list_selection = (list_selection - 1 + game_list.size()) % game_list.size();
                        }
                        break;
                        
                    case KEY_DOWN:
                        if (!game_list.empty()) {
                            list_selection = (list_selection + 1) % game_list.size();
                        }
                        break;
                        
                    case 10: // Enter key
                        if (!game_list.empty()) {
                            selected_game = game_list[list_selection];
                            current_level = GAME_DETAILS;
                        }
                        break;
                        
                    case 27: // ESC key
                    case 'q':
                    case 'Q':
                        // Go back to the appropriate menu
                        if (search_query == "All Games" || search_query == "Available Games") {
                            current_level = BROWSE_MENU;
                        } else {
                            current_level = MAIN_MENU;
                        }
                        break;
                }
                break;
                
            case HISTORY_DISPLAY:
            case RECOMMEND_DISPLAY:
                if (ch == 27 || ch == 'q' || ch == 'Q') { // ESC key or q
                    current_level = MAIN_MENU;
                }
                break;
        }
    }
    
    // Exit menu interface
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