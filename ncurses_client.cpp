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

// Helper function to set grey border color
void set_border_color(WINDOW* win) {
    if (has_colors()) {
        wattron(win, COLOR_PAIR(5)); // Grey border color
    }
}

// Helper function to unset grey border color
void unset_border_color(WINDOW* win) {
    if (has_colors()) {
        wattroff(win, COLOR_PAIR(5)); // Grey border color
    }
}

// Helper function to set transparent background for a window
void set_transparent_background(WINDOW* win) {
    if (has_colors()) {
        wbkgd(win, COLOR_PAIR(0)); // Use default terminal colors for background
    }
}

// Display a message box with the given message
void display_message_box(const std::string& message) {
    int height, width;
    getmaxyx(stdscr, height, width);
    
    WINDOW* win = newwin(6, width - 20, height/2 - 3, 10);
    set_border_color(win);
    box(win, 0, 0);
    unset_border_color(win);
    
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
    
    // Create a border around the entire screen
    set_border_color(stdscr);
    box(stdscr, 0, 0);
    unset_border_color(stdscr);
    
    // Calculate centered positions - make the form wider
    int form_width = 70;  // Increased from 50 to 70
    int form_height = 14; // Increased from 12 to 14
    int start_x = (width - form_width) / 2;
    int start_y = (height - form_height) / 2;
    
    // Create centered form window with border
    WINDOW* form_win = newwin(form_height, form_width, start_y, start_x);
    set_border_color(form_win);
    box(form_win, 0, 0);
    unset_border_color(form_win);
    
    // Print title using bold centered text
    wattron(form_win, A_BOLD);
    mvwprintw(form_win, 0, (form_width - 19) / 2, " GAME RENTAL SYSTEM ");
    wattroff(form_win, A_BOLD);
    
    // Print login instructions centered
    wattron(form_win, A_BOLD);
    mvwprintw(form_win, 2, (form_width - 30) / 2, "USER LOGIN / CREATE ACCOUNT");
    wattroff(form_win, A_BOLD);
    
    // Consistent vertical spacing between forms - add additional line for alignment
    mvwprintw(form_win, 3, (form_width - 40) / 2, "Welcome! Please enter your username below.");
    
    // Basic instructions centered - moved to line 5 to match password form
    mvwprintw(form_win, 5, (form_width - 47) / 2, "Enter your username to login or create a new account");
    
    // Create the input window with border at the same position as password form
    WINDOW* input_win = newwin(3, 40, (height - form_height) / 2 + 8, (width - 40) / 2);
    set_border_color(input_win);
    box(input_win, 0, 0);
    unset_border_color(input_win);
    
    // Add placeholder text inside the input box
    wattron(input_win, A_DIM); // Dim attribute for placeholder text
    mvwprintw(input_win, 1, 1, "Enter username...");
    wattroff(input_win, A_DIM);
    
    // Error message will be displayed below the input box - init with empty space
    attron(COLOR_PAIR(3)); // Red text for error
    mvprintw((height - form_height) / 2 + 11, (width - 50) / 2, "                                                  ");
    attroff(COLOR_PAIR(3));
    
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
    bool first_keypress = true; // Track if this is the first keypress
    
    // Position cursor at start of input field inside the input box (accounting for border)
    wmove(input_win, 1, 1);
    curs_set(1); // Make cursor visible
    keypad(input_win, TRUE); // Enable special keys
    noecho(); // Don't echo characters (we'll handle display manually)
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
                // Show error in red below the input box
                if (has_colors()) {
                    attron(COLOR_PAIR(3)); // Red text for error
                }
                mvprintw((height - form_height) / 2 + 11, (width - 45) / 2, "Username cannot be empty. Please enter a username.");
                if (has_colors()) {
                    attroff(COLOR_PAIR(3));
                }
                refresh(); // Use main screen refresh
                
                // Show placeholder again
                werase(input_win);
                set_border_color(input_win);
                box(input_win, 0, 0);
                unset_border_color(input_win);
                wattron(input_win, A_DIM);
                mvwprintw(input_win, 1, 1, "Enter username...");
                wattroff(input_win, A_DIM);
                first_keypress = true;
                
                // Move cursor back to input position
                wmove(input_win, 1, 1);
                wrefresh(input_win);
                continue;
            }
            
            // Show checking message below the input box
            mvprintw((height - form_height) / 2 + 11, (width - 20) / 2, "Checking username...");
            refresh(); // Use main screen refresh
            
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
                // Replace with space
                wmove(input_win, 1, 1 + pos);
                waddch(input_win, ' ');
                // Position cursor correctly
                wmove(input_win, 1, 1 + pos);
                wrefresh(input_win);
                
                // If we deleted all characters, show the placeholder again
                if (pos == 0) {
                    werase(input_win);
                    set_border_color(input_win);
                    box(input_win, 0, 0);
                    unset_border_color(input_win);
                    wattron(input_win, A_DIM);
                    mvwprintw(input_win, 1, 1, "Enter username...");
                    wattroff(input_win, A_DIM);
                    first_keypress = true;
                    wrefresh(input_win);
                }
            }
        }
        else if (pos < 38 && ch >= 32 && ch <= 126) { // Printable characters - increased limit for wider boxes
            // Clear the placeholder text on first keypress
            if (first_keypress) {
                werase(input_win);
                set_border_color(input_win);
                box(input_win, 0, 0);
                unset_border_color(input_win);
                first_keypress = false;
                wrefresh(input_win);
            }
            
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
    set_border_color(stdscr);
    box(stdscr, 0, 0);
    unset_border_color(stdscr);
    
    // Calculate centered positions - make the form wider and taller
    int form_width = 70;  // Increased width
    int form_height = 14; // Same height for both forms
    int start_x = (width - form_width) / 2;
    int start_y = (height - form_height) / 2;
    
    // Create centered form window with border
    WINDOW* form_win = newwin(form_height, form_width, start_y, start_x);
    set_border_color(form_win);
    box(form_win, 0, 0);
    unset_border_color(form_win);
    
    // Print title using bold centered text
    wattron(form_win, A_BOLD);
    mvwprintw(form_win, 0, (form_width - 19) / 2, " GAME RENTAL SYSTEM ");
    wattroff(form_win, A_BOLD);
    
    // User status with better messages for new users
    wattron(form_win, A_BOLD);
    if (is_new_user) {
        mvwprintw(form_win, 2, (form_width - 16) / 2, "CREATE NEW ACCOUNT");
        mvwprintw(form_win, 3, (form_width - 45) / 2, "Welcome, %s! You're creating a new account.", username.c_str());
        
        // Instructions with more details for new users
        mvwprintw(form_win, 5, (form_width - 43) / 2, "Please choose a password for your new account");
        mvwprintw(form_win, 6, (form_width - 40) / 2, "(You'll need to enter it twice for verification)");
    } else {
        mvwprintw(form_win, 2, (form_width - 10) / 2, "USER LOGIN");
        mvwprintw(form_win, 3, (form_width - 42) / 2, "Welcome back, %s! Please enter your password.", username.c_str());
        
        // Instructions for returning users
        mvwprintw(form_win, 5, (form_width - 33) / 2, "Please enter your password to log in");
    }
    wattroff(form_win, A_BOLD);
    
    // Create password input window with border at consistent position
    WINDOW* pass_win = newwin(3, 40, (height - form_height) / 2 + 8, (width - 40) / 2);
    set_border_color(pass_win);
    box(pass_win, 0, 0);
    unset_border_color(pass_win);
    
    // Add placeholder text inside the password box
    wattron(pass_win, A_DIM); // Dim attribute for placeholder text
    mvwprintw(pass_win, 1, 1, "Enter password...");
    wattroff(pass_win, A_DIM);
    
    // Error message will be displayed below the input box - init with empty space
    attron(COLOR_PAIR(3)); // Red text for error
    mvprintw((height - form_height) / 2 + 11, (width - 50) / 2, "                                                  ");
    attroff(COLOR_PAIR(3));
    
    // If it's a new user, create a confirmation window too
    WINDOW* confirm_win = nullptr;
    if (is_new_user) {
        // Use a separate form height for new users that need confirmation
        form_height = 18;
        
        confirm_win = newwin(3, 40, (height - form_height) / 2 + 12, (width - 40) / 2);
        set_border_color(confirm_win);
        box(confirm_win, 0, 0);
        unset_border_color(confirm_win);
        
        // Add placeholder text inside the confirmation box
        wattron(confirm_win, A_DIM);
        mvwprintw(confirm_win, 1, 1, "Confirm password...");
        wattroff(confirm_win, A_DIM);
        
        // Error message for new users will be displayed below the confirmation box
        attron(COLOR_PAIR(3));
        mvprintw((height - form_height) / 2 + 15, (width - 50) / 2, "                                                  ");
        attroff(COLOR_PAIR(3));
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
    bool first_keypress = true; // Flag to track if this is the first keypress
    
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
                // Empty password - show error in red below the input box
                if (has_colors()) {
                    attron(COLOR_PAIR(3)); // Red text for error
                }
                mvprintw((height - form_height) / 2 + 11, (width - 47) / 2, "Password cannot be empty. Please enter a password.");
                if (has_colors()) {
                    attroff(COLOR_PAIR(3));
                }
                refresh(); // Use main screen refresh
                
                // Show placeholder again
                werase(pass_win);
                set_border_color(pass_win);
                box(pass_win, 0, 0);
                unset_border_color(pass_win);
                wattron(pass_win, A_DIM);
                mvwprintw(pass_win, 1, 1, "Enter password...");
                wattroff(pass_win, A_DIM);
                first_keypress = true;
                
                // Move cursor back to password field
                wmove(pass_win, 1, 1);
                wrefresh(pass_win);
                continue;
            }
            
            if (is_new_user) {
                // Now get confirmation password
                pos = 0;
                bool confirm_first_keypress = true;
                
                // Completely redraw the screen to fix the visibility issue
                clear(); // Clear the screen first
                
                // Redraw the main border
                set_border_color(stdscr);
                box(stdscr, 0, 0);
                unset_border_color(stdscr);
                
                // Redraw the form and its content
                set_border_color(form_win);
                box(form_win, 0, 0);
                unset_border_color(form_win);
                
                wattron(form_win, A_BOLD);
                mvwprintw(form_win, 0, (form_width - 19) / 2, " GAME RENTAL SYSTEM ");
                mvwprintw(form_win, 2, (form_width - 16) / 2, "CREATE NEW ACCOUNT");
                mvwprintw(form_win, 3, (form_width - 45) / 2, "Welcome, %s! You're creating a new account.", username.c_str());
                wattroff(form_win, A_BOLD);
                
                // Redraw instructions
                mvwprintw(form_win, 5, (form_width - 43) / 2, "Please choose a password for your new account");
                mvwprintw(form_win, 6, (form_width - 40) / 2, "(You'll need to enter it twice for verification)");
                
                // Redraw bottom instructions
                mvwprintw(form_win, form_height - 2, (form_width - 43) / 2, "Press ENTER to create account or ESC to go back");
                
                wrefresh(form_win);
                
                // Redraw the password window to show it's already been filled
                for (int i = 0; i < strlen(password); i++) {
                    mvwaddch(pass_win, 1, 1 + i, '*');
                }
                wrefresh(pass_win);
                
                // Move to confirmation field
                wmove(confirm_win, 1, 1);
                wrefresh(confirm_win);
                
                // Full screen refresh to ensure everything is visible
                refresh();
                
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
                            
                            // If we deleted all characters, show the placeholder again
                            if (pos == 0) {
                                werase(confirm_win);
                                set_border_color(confirm_win);
                                box(confirm_win, 0, 0);
                                unset_border_color(confirm_win);
                                wattron(confirm_win, A_DIM);
                                mvwprintw(confirm_win, 1, 1, "Confirm password...");
                                wattroff(confirm_win, A_DIM);
                                confirm_first_keypress = true;
                                wrefresh(confirm_win);
                            }
                        }
                    }
                    else if (pos < 38 && ch >= 32 && ch <= 126) { // Printable characters - increased limit for wider boxes
                        // Clear the placeholder text on first keypress
                        if (confirm_first_keypress) {
                            werase(confirm_win);
                            set_border_color(confirm_win);
                            box(confirm_win, 0, 0);
                            unset_border_color(confirm_win);
                            confirm_first_keypress = false;
                            wrefresh(confirm_win);
                        }
                        
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
                    // Show error in red below the confirmation box
                    if (has_colors()) {
                        attron(COLOR_PAIR(3)); // Red text for error
                    }
                    mvprintw((height - form_height) / 2 + 15, (width - 40) / 2, "Passwords do not match. Please try again.");
                    if (has_colors()) {
                        attroff(COLOR_PAIR(3));
                    }
                    refresh(); // Use main screen refresh
                    
                    // Clear password fields and reset placeholders
                    werase(pass_win);
                    set_border_color(pass_win);
                    box(pass_win, 0, 0);
                    unset_border_color(pass_win);
                    wattron(pass_win, A_DIM);
                    mvwprintw(pass_win, 1, 1, "Enter password...");
                    wattroff(pass_win, A_DIM);
                    first_keypress = true;
                    wrefresh(pass_win);
                    
                    werase(confirm_win);
                    set_border_color(confirm_win);
                    box(confirm_win, 0, 0);
                    unset_border_color(confirm_win);
                    wattron(confirm_win, A_DIM);
                    mvwprintw(confirm_win, 1, 1, "Confirm password...");
                    wattroff(confirm_win, A_DIM);
                    wrefresh(confirm_win);
                    
                    // Reset position and start over with password
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
                set_border_color(msg_win);
                box(msg_win, 0, 0);
                unset_border_color(msg_win);
                
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
                    set_border_color(progress_win);
                    box(progress_win, 0, 0);
                    unset_border_color(progress_win);
                    
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
                    set_border_color(progress_win);
                    box(progress_win, 0, 0);
                    unset_border_color(progress_win);
                    
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
                
                // If we deleted all characters, show the placeholder again
                if (pos == 0) {
                    werase(pass_win);
                    set_border_color(pass_win);
                    box(pass_win, 0, 0);
                    unset_border_color(pass_win);
                    wattron(pass_win, A_DIM);
                    mvwprintw(pass_win, 1, 1, "Enter password...");
                    wattroff(pass_win, A_DIM);
                    first_keypress = true;
                    wrefresh(pass_win);
                }
            }
        }
        else if (pos < 38 && ch >= 32 && ch <= 126) { // Printable characters - increased limit for wider boxes
            // Clear the placeholder text on first keypress
            if (first_keypress) {
                werase(pass_win);
                set_border_color(pass_win);
                box(pass_win, 0, 0);
                unset_border_color(pass_win);
                first_keypress = false;
                wrefresh(pass_win);
            }
            
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
        
        // Create content area with grey border
        set_border_color(stdscr);
        box(stdscr, 0, 0);
        unset_border_color(stdscr);
        
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
                                    // Execute search and display results directly
                                    std::string search_results = send_command_and_get_response("SEARCH " + search_query);
                                    
                                    // Clear game list before adding new entries
                                    game_list.clear();
                                    
                                    // Parse and store all lines first
                                    std::vector<std::string> all_search_lines;
                                    std::istringstream search_iss(search_results);
                                    std::string search_line;
                                    
                                    // Process all lines and build game list
                                    while (std::getline(search_iss, search_line)) {
                                        all_search_lines.push_back(search_line);
                                        
                                        // Add game titles to the game list for possible selection
                                        if (!search_line.empty() && 
                                            search_line[0] != '-' && !isdigit(search_line[0]) && 
                                            search_line.find(':') == std::string::npos) {
                                            game_list.push_back(search_line);
                                        }
                                    }
                                    
                                    // Create a scrollable display with paging
                                    int current_page = 0;
                                    int lines_per_page = height - 10; // Leave room for header and footer
                                    int total_pages = (all_search_lines.size() + lines_per_page - 1) / lines_per_page;
                                    
                                    bool search_done = false;
                                    while (!search_done) {
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        // Title
                                        attron(A_BOLD);
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(4)); // Yellow for title
                                        }
                                        mvprintw(1, (width - 20) / 2, "SEARCH RESULTS FOR: ");
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(4));
                                        }
                                        attroff(A_BOLD);
                                        
                                        // Display search query
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(3)); // Red for search term
                                        }
                                        mvprintw(1, (width + 20) / 2, "\"%s\"", search_query.c_str());
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(3));
                                        }
                                        
                                        // Show page info
                                        mvprintw(2, (width - 20) / 2, "Page %d of %d", current_page + 1, total_pages > 0 ? total_pages : 1);
                                        
                                        // Display the current page of results
                                        int start_idx = current_page * lines_per_page;
                                        int end_idx = std::min(start_idx + lines_per_page, (int)all_search_lines.size());
                                        
                                        for (int i = start_idx, line = 4; i < end_idx; i++, line++) {
                                            // Format status codes differently
                                            if (all_search_lines[i].length() >= 3 && isdigit(all_search_lines[i][0]) && 
                                                isdigit(all_search_lines[i][1]) && isdigit(all_search_lines[i][2])) {
                                                if (has_colors()) {
                                                    attron(COLOR_PAIR(2)); // Green for status
                                                }
                                                mvprintw(line, 2, "Status: %s", all_search_lines[i].c_str());
                                                if (has_colors()) {
                                                    attroff(COLOR_PAIR(2));
                                                }
                                            } 
                                            // Format game titles with bullet points
                                            else if (!all_search_lines[i].empty() && 
                                                    all_search_lines[i][0] != '-' && !isdigit(all_search_lines[i][0]) && 
                                                    all_search_lines[i].find(':') == std::string::npos) {
                                                // Highlight game titles
                                                if (has_colors()) {
                                                    attron(COLOR_PAIR(4)); // Yellow for game titles
                                                }
                                                mvprintw(line, 2, "• %s", all_search_lines[i].c_str());
                                                if (has_colors()) {
                                                    attroff(COLOR_PAIR(4));
                                                }
                                            } 
                                            // Print other lines normally
                                            else if (!all_search_lines[i].empty()) {
                                                mvprintw(line, 2, "%s", all_search_lines[i].c_str());
                                            }
                                        }
                                        
                                        // Instructions
                                        mvprintw(height - 6, 2, "UP/DOWN: Navigate pages, ENTER: Continue, ESC: Return to menu");
                                        
                                        refresh();
                                        
                                        // Handle navigation
                                        int ch = getch();
                                        switch (ch) {
                                            case KEY_UP:
                                            case 'k':  // Vim-style up
                                                if (current_page > 0) {
                                                    current_page--;
                                                }
                                                break;
                                                
                                            case KEY_DOWN:
                                            case 'j':  // Vim-style down
                                                if (current_page < total_pages - 1) {
                                                    current_page++;
                                                }
                                                break;
                                                
                                            case 10:   // Enter - proceed to game selection
                                                search_done = true;
                                                break;
                                                
                                            case 27:   // Escape - return to main menu
                                            case 'q':  // q to quit
                                                search_done = true;
                                                current_level = MAIN_MENU;
                                                return; // Exit the current function
                                        }
                                    }
                                    
                                    // Instructions for further actions
                                    if (!game_list.empty()) {
                                        // Allow for game selection
                                        mvprintw(height - 4, 2, "Enter a game name to view details: ");
                                        
                                        // Get game name
                                        echo();
                                        curs_set(1);
                                        char game_name[256] = {0};
                                        getnstr(game_name, 255);
                                        noecho();
                                        curs_set(0);
                                        
                                        if (strlen(game_name) > 0) {
                                            // Get and display game details
                                            std::string details = send_command_and_get_response("SHOW " + std::string(game_name));
                                            
                                            // Display game details
                                            clear();
                                            box(stdscr, 0, 0);
                                            
                                            // Title
                                            attron(A_BOLD);
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(4)); // Yellow for title
                                            }
                                            mvprintw(1, (width - 12) / 2, "GAME DETAILS");
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(4));
                                            }
                                            attroff(A_BOLD);
                                            
                                            // Game name
                                            attron(A_BOLD);
                                            mvprintw(3, 2, "Game: %s", game_name);
                                            attroff(A_BOLD);
                                            
                                            // Display details
                                            int details_line = 5;
                                            std::istringstream det_iss(details);
                                            std::string det_line;
                                            
                                            while (std::getline(det_iss, det_line) && details_line < height - 6) {
                                                mvprintw(details_line++, 2, "%s", det_line.c_str());
                                            }
                                            
                                            // Allow checkout option
                                            mvprintw(height - 4, 2, "Press 'R' to rent this game, any other key to return");
                                            refresh();
                                            
                                            if (getch() == 'r' || getch() == 'R') {
                                                // Checkout the game
                                                std::string checkout_response = send_command_and_get_response("CHECKOUT " + std::string(game_name));
                                                
                                                // Display checkout result
                                                clear();
                                                box(stdscr, 0, 0);
                                                
                                                attron(A_BOLD);
                                                mvprintw(2, (width - 16) / 2, "CHECKOUT RESULT");
                                                attroff(A_BOLD);
                                                
                                                // Display full server response
                                                mvprintw(4, 2, "Server response:");
                                                int checkout_result_line = 5;
                                                std::istringstream resp_iss(checkout_response);
                                                std::string resp_line;
                                                
                                                while (std::getline(resp_iss, resp_line) && checkout_result_line < height - 4) {
                                                    mvprintw(checkout_result_line++, 4, "%s", resp_line.c_str());
                                                }
                                                
                                                // Wait for key press
                                                mvprintw(height - 2, 2, "Press any key to return to menu");
                                                refresh();
                                                getch();
                                            }
                                        }
                                    } else {
                                        // No games found
                                        mvprintw(height - 4, 2, "No games found. Press any key to return to menu");
                                        refresh();
                                        getch();
                                    }
                                    
                                    // Return to main menu
                                    current_level = MAIN_MENU;
                                }
                            }
                            else if (main_selection == 4) { // View History
                                // Get rental history
                                std::string history = send_command_and_get_response("HISTORY");
                                
                                // Display the history in a full-screen view
                                clear();
                                box(stdscr, 0, 0);
                                
                                // Title
                                attron(A_BOLD);
                                if (has_colors()) {
                                    attron(COLOR_PAIR(4)); // Yellow for title
                                }
                                mvprintw(1, (width - 14) / 2, "RENTAL HISTORY");
                                if (has_colors()) {
                                    attroff(COLOR_PAIR(4));
                                }
                                attroff(A_BOLD);
                                
                                // Display the history with formatting
                                int line = 3;
                                std::istringstream iss(history);
                                std::string history_line;
                                
                                while (std::getline(iss, history_line) && line < height - 4) {
                                    // Format status codes differently
                                    if (history_line.length() >= 3 && isdigit(history_line[0]) && 
                                        isdigit(history_line[1]) && isdigit(history_line[2])) {
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(2)); // Green for status
                                        }
                                        mvprintw(line++, 2, "Status: %s", history_line.c_str());
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(2));
                                        }
                                    } 
                                    // Format game titles with bullet points
                                    else if (!history_line.empty() && 
                                             history_line[0] != '-' && !isdigit(history_line[0]) && 
                                             history_line.find(':') == std::string::npos) {
                                        mvprintw(line++, 2, "• %s", history_line.c_str());
                                    } 
                                    // Print other lines normally
                                    else if (!history_line.empty()) {
                                        mvprintw(line++, 2, "%s", history_line.c_str());
                                    }
                                }
                                
                                // Instructions
                                mvprintw(height - 2, 2, "Press any key to return to menu");
                                refresh();
                                getch();
                                
                                // Return to main menu
                                current_level = MAIN_MENU;
                            }
                            else if (main_selection == 5) { // Get Recommendations
                                // Get recommendations
                                std::string recommendations = send_command_and_get_response("RECOMMEND");
                                
                                // Display the recommendations in a full-screen view
                                clear();
                                box(stdscr, 0, 0);
                                
                                // Title
                                attron(A_BOLD);
                                if (has_colors()) {
                                    attron(COLOR_PAIR(4)); // Yellow for title
                                }
                                mvprintw(1, (width - 17) / 2, "RECOMMENDATIONS");
                                if (has_colors()) {
                                    attroff(COLOR_PAIR(4));
                                }
                                attroff(A_BOLD);
                                
                                // Display the recommendations with formatting
                                int line = 3;
                                std::istringstream iss(recommendations);
                                std::string rec_line;
                                
                                while (std::getline(iss, rec_line) && line < height - 4) {
                                    // Format status codes differently
                                    if (rec_line.length() >= 3 && isdigit(rec_line[0]) && 
                                        isdigit(rec_line[1]) && isdigit(rec_line[2])) {
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(2)); // Green for status
                                        }
                                        mvprintw(line++, 2, "Status: %s", rec_line.c_str());
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(2));
                                        }
                                    } 
                                    // Format game titles with bullet points
                                    else if (!rec_line.empty() && 
                                             rec_line[0] != '-' && !isdigit(rec_line[0]) && 
                                             rec_line.find(':') == std::string::npos) {
                                        mvprintw(line++, 2, "• %s", rec_line.c_str());
                                    } 
                                    // Print other lines normally
                                    else if (!rec_line.empty()) {
                                        mvprintw(line++, 2, "%s", rec_line.c_str());
                                    }
                                }
                                
                                // Instructions
                                mvprintw(height - 2, 2, "Press any key to return to menu");
                                refresh();
                                getch();
                                
                                // Return to main menu
                                current_level = MAIN_MENU;
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
                                    {
                                    // Execute LIST command to show all games
                                    std::string list_response = send_command_and_get_response("LIST");
                                    
                                    // Show the response in a fullscreen window
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 9) / 2, "ALL GAMES");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // Parse and store all lines first
                                    std::vector<std::string> all_lines;
                                    std::istringstream list_iss(list_response);
                                    std::string list_resp_line;
                                    
                                    while (std::getline(list_iss, list_resp_line)) {
                                        all_lines.push_back(list_resp_line);
                                    }
                                    
                                    // Create a scrollable display with paging
                                    int current_page = 0;
                                    int lines_per_page = height - 7; // Leave room for header and footer
                                    int total_pages = (all_lines.size() + lines_per_page - 1) / lines_per_page;
                                    
                                    bool done = false;
                                    while (!done) {
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        // Title
                                        attron(A_BOLD);
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(4)); // Yellow for title
                                        }
                                        mvprintw(1, (width - 9) / 2, "ALL GAMES");
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(4));
                                        }
                                        attroff(A_BOLD);
                                        
                                        // Show page info
                                        mvprintw(2, (width - 20) / 2, "Page %d of %d", current_page + 1, total_pages > 0 ? total_pages : 1);
                                        
                                        // Display the current page of results
                                        int start_idx = current_page * lines_per_page;
                                        int end_idx = std::min(start_idx + lines_per_page, (int)all_lines.size());
                                        
                                        for (int i = start_idx, line = 3; i < end_idx; i++, line++) {
                                            // If this is a status code line (starts with digits)
                                            if (all_lines[i].length() >= 3 && isdigit(all_lines[i][0]) && 
                                                isdigit(all_lines[i][1]) && isdigit(all_lines[i][2])) {
                                                if (has_colors()) {
                                                    attron(COLOR_PAIR(2)); // Green for status
                                                }
                                                mvprintw(line, 2, "Status: %s", all_lines[i].c_str());
                                                if (has_colors()) {
                                                    attroff(COLOR_PAIR(2));
                                                }
                                            }
                                            // If this looks like a game title (not starting with digits or special chars)
                                            else if (!all_lines[i].empty() && 
                                                    all_lines[i][0] != '-' && !isdigit(all_lines[i][0]) && 
                                                    all_lines[i].find(':') == std::string::npos) {
                                                mvprintw(line, 2, "• %s", all_lines[i].c_str());
                                            }
                                            // Other lines
                                            else {
                                                mvprintw(line, 2, "%s", all_lines[i].c_str());
                                            }
                                        }
                                        
                                        // Instructions
                                        mvprintw(height - 2, 2, "UP/DOWN: Navigate pages, ENTER/ESC: Return to menu");
                                        refresh();
                                        
                                        // Handle navigation
                                        int ch = getch();
                                        switch (ch) {
                                            case KEY_UP:
                                            case 'k':  // Vim-style up
                                                if (current_page > 0) {
                                                    current_page--;
                                                }
                                                break;
                                                
                                            case KEY_DOWN:
                                            case 'j':  // Vim-style down
                                                if (current_page < total_pages - 1) {
                                                    current_page++;
                                                }
                                                break;
                                                
                                            case 10:   // Enter
                                            case 27:   // Escape
                                            case 'q':  // q to quit
                                                done = true;
                                                break;
                                        }
                                    }
                                    
                                    refresh();
                                    getch();
                                    
                                    // Return to browse menu
                                    current_level = BROWSE_MENU;
                                    }
                                    break;
                                    
                                case 1: // List by Genre
                                    {
                                    // Show genre selection
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 15) / 2, "BROWSE BY GENRE");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // Hardcoded list of common genres
                                    const char* genres[] = {
                                        "Action", "Adventure", "RPG", "Strategy", 
                                        "Simulation", "Sports", "Racing", "Puzzle"
                                    };
                                    
                                    // Display instructions
                                    mvprintw(3, 2, "Select a genre to browse:");
                                    
                                    // Display genres
                                    for (int i = 0; i < 8; i++) {
                                        mvprintw(5 + i, 4, "• %s", genres[i]);
                                    }
                                    
                                    // Input prompt
                                    mvprintw(height - 6, 2, "Enter a genre: ");
                                    
                                    // Get genre
                                    echo();
                                    curs_set(1);
                                    char genre_name[256] = {0};
                                    getnstr(genre_name, 255);
                                    noecho();
                                    curs_set(0);
                                    
                                    if (strlen(genre_name) > 0) {
                                        // Execute SEARCH command with genre
                                        std::string search_cmd = "SEARCH genre:" + std::string(genre_name);
                                        std::string genre_results = send_command_and_get_response(search_cmd);
                                        
                                        // Display results
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        // Title
                                        attron(A_BOLD);
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(4)); // Yellow for title
                                        }
                                        mvprintw(1, (width - 40) / 2, "GAMES IN GENRE: %s", genre_name);
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(4));
                                        }
                                        attroff(A_BOLD);
                                        
                                        // Display the results
                                        int genre_line = 3;
                                        std::istringstream genre_iss(genre_results);
                                        std::string genre_result_line;
                                        
                                        while (std::getline(genre_iss, genre_result_line) && genre_line < height - 4) {
                                            mvprintw(genre_line++, 2, "%s", genre_result_line.c_str());
                                        }
                                        
                                        // Wait for key press
                                        mvprintw(height - 2, 2, "Press any key to return to menu");
                                        refresh();
                                        getch();
                                    }
                                    
                                    // Return to browse menu
                                    current_level = BROWSE_MENU;
                                    }
                                    break;
                                    
                                case 2: // List by Platform
                                    {
                                    // Show platform selection
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 18) / 2, "BROWSE BY PLATFORM");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // Hardcoded list of common platforms
                                    const char* platforms[] = {
                                        "PC", "PlayStation", "Xbox", "Switch", 
                                        "Mobile", "VR", "Arcade", "Retro"
                                    };
                                    
                                    // Display instructions
                                    mvprintw(3, 2, "Select a platform to browse:");
                                    
                                    // Display platforms
                                    for (int i = 0; i < 8; i++) {
                                        mvprintw(5 + i, 4, "• %s", platforms[i]);
                                    }
                                    
                                    // Input prompt
                                    mvprintw(height - 6, 2, "Enter a platform: ");
                                    
                                    // Get platform
                                    echo();
                                    curs_set(1);
                                    char platform_name[256] = {0};
                                    getnstr(platform_name, 255);
                                    noecho();
                                    curs_set(0);
                                    
                                    if (strlen(platform_name) > 0) {
                                        // Execute SEARCH command with platform
                                        std::string platform_cmd = "SEARCH platform:" + std::string(platform_name);
                                        std::string platform_results = send_command_and_get_response(platform_cmd);
                                        
                                        // Display results
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        // Title
                                        attron(A_BOLD);
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(4)); // Yellow for title
                                        }
                                        mvprintw(1, (width - 40) / 2, "GAMES ON PLATFORM: %s", platform_name);
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(4));
                                        }
                                        attroff(A_BOLD);
                                        
                                        // Display the results
                                        int platform_line = 3;
                                        std::istringstream platform_iss(platform_results);
                                        std::string platform_result_line;
                                        
                                        while (std::getline(platform_iss, platform_result_line) && platform_line < height - 4) {
                                            mvprintw(platform_line++, 2, "%s", platform_result_line.c_str());
                                        }
                                        
                                        // Wait for key press
                                        mvprintw(height - 2, 2, "Press any key to return to menu");
                                        refresh();
                                        getch();
                                    }
                                    
                                    // Return to browse menu
                                    current_level = BROWSE_MENU;
                                    }
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
                                    {
                                    // Show game checkout interface
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 15) / 2, "CHECKOUT A GAME");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // Get list of available games
                                    std::string checkout_games_list = send_command_and_get_response("LIST");
                                    
                                    // Parse and store all lines first
                                    std::vector<std::string> checkout_lines;
                                    std::istringstream checkout_iss(checkout_games_list);
                                    std::string checkout_line;
                                    
                                    while (std::getline(checkout_iss, checkout_line)) {
                                        checkout_lines.push_back(checkout_line);
                                    }
                                    
                                    // Create a scrollable display with paging
                                    int checkout_page = 0;
                                    int checkout_lines_per_page = height - 14; // Leave room for header and footer plus input
                                    int checkout_total_pages = (checkout_lines.size() + checkout_lines_per_page - 1) / checkout_lines_per_page;
                                    
                                    bool checkout_browsing = true;
                                    while (checkout_browsing) {
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        // Title
                                        attron(A_BOLD);
                                        if (has_colors()) {
                                            attron(COLOR_PAIR(4)); // Yellow for title
                                        }
                                        mvprintw(1, (width - 15) / 2, "CHECKOUT A GAME");
                                        if (has_colors()) {
                                            attroff(COLOR_PAIR(4));
                                        }
                                        attroff(A_BOLD);
                                        
                                        // Display instructions
                                        mvprintw(3, 2, "Available games:");
                                        
                                        // Show page info
                                        mvprintw(4, (width - 20) / 2, "Page %d of %d", checkout_page + 1, checkout_total_pages > 0 ? checkout_total_pages : 1);
                                        
                                        // Display the current page of results
                                        int start_idx = checkout_page * checkout_lines_per_page;
                                        int end_idx = std::min(start_idx + checkout_lines_per_page, (int)checkout_lines.size());
                                        
                                        for (int i = start_idx, line = 5; i < end_idx; i++, line++) {
                                            // If this is a status code line (starts with digits)
                                            if (checkout_lines[i].length() >= 3 && isdigit(checkout_lines[i][0]) && 
                                                isdigit(checkout_lines[i][1]) && isdigit(checkout_lines[i][2])) {
                                                if (has_colors()) {
                                                    attron(COLOR_PAIR(2)); // Green for status
                                                }
                                                mvprintw(line, 2, "Status: %s", checkout_lines[i].c_str());
                                                if (has_colors()) {
                                                    attroff(COLOR_PAIR(2));
                                                }
                                            }
                                            // If this looks like a game title
                                            else if (!checkout_lines[i].empty() && 
                                                    checkout_lines[i][0] != '-' && !isdigit(checkout_lines[i][0]) && 
                                                    checkout_lines[i].find(':') == std::string::npos) {
                                                mvprintw(line, 4, "• %s", checkout_lines[i].c_str());
                                            }
                                            // Other lines
                                            else {
                                                mvprintw(line, 4, "%s", checkout_lines[i].c_str());
                                            }
                                        }
                                        
                                        // Navigation instructions
                                        mvprintw(height - 10, 2, "UP/DOWN: Navigate pages, ENTER: Proceed to checkout, ESC: Cancel");
                                        refresh();
                                        
                                        // Handle navigation
                                        int ch = getch();
                                        switch (ch) {
                                            case KEY_UP:
                                            case 'k':  // Vim-style up
                                                if (checkout_page > 0) {
                                                    checkout_page--;
                                                }
                                                break;
                                                
                                            case KEY_DOWN:
                                            case 'j':  // Vim-style down
                                                if (checkout_page < checkout_total_pages - 1) {
                                                    checkout_page++;
                                                }
                                                break;
                                                
                                            case 10:   // Enter - proceed to checkout
                                                checkout_browsing = false;
                                                break;
                                                
                                            case 27:   // Escape - return to rent menu
                                            case 'q':  // q to quit
                                                current_level = RENT_MENU;
                                                return; // Exit the current function
                                        }
                                    }
                                    
                                    // Input prompt
                                    mvprintw(height - 8, 2, "Enter game name to checkout: ");
                                    
                                    // Get game name
                                    echo();
                                    curs_set(1);
                                    char game_name1[256] = {0};
                                    getnstr(game_name1, 255);
                                    noecho();
                                    curs_set(0);
                                    
                                    if (strlen(game_name1) > 0) {
                                        // Send checkout command
                                        std::string checkout_response = send_command_and_get_response("CHECKOUT " + std::string(game_name1));
                                        
                                        // Display result
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        attron(A_BOLD);
                                        mvprintw(2, (width - 16) / 2, "CHECKOUT RESULT");
                                        attroff(A_BOLD);
                                        
                                        // Parse response to show success/failure status
                                        if (checkout_response.find("success") != std::string::npos || 
                                            checkout_response.find("200") != std::string::npos) {
                                            // Success message
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(2)); // Green for success
                                            }
                                            mvprintw(4, 2, "SUCCESS: Game checked out successfully!");
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(2));
                                            }
                                        } else {
                                            // Error message
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(3)); // Red for error
                                            }
                                            mvprintw(4, 2, "ERROR: Failed to checkout game.");
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(3));
                                            }
                                        }
                                        
                                        // Display full server response
                                        mvprintw(6, 2, "Server response:");
                                        int line_num1 = 7;
                                        std::istringstream resp_iss1(checkout_response);
                                        std::string resp_line1;
                                        
                                        while (std::getline(resp_iss1, resp_line1) && line_num1 < height - 4) {
                                            mvprintw(line_num1++, 4, "%s", resp_line1.c_str());
                                        }
                                    }
                                    
                                    // Wait for key press
                                    mvprintw(height - 2, 2, "Press any key to return to menu");
                                    refresh();
                                    getch();
                                    
                                    // Return to rent menu
                                    current_level = RENT_MENU;
                                    break;
                                    }
                                    
                                case 1: // Return Game
                                    {
                                    // Show game return interface
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 14) / 2, "RETURN A GAME");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // First get a list of currently rented games
                                    std::string rented_games2 = send_command_and_get_response("MYGAMES");
                                    
                                    // Display instructions
                                    mvprintw(3, 2, "Your currently rented games:");
                                    
                                    // Display the list
                                    int line2 = 5;
                                    std::istringstream iss2(rented_games2);
                                    std::string list_line2;
                                    
                                    while (std::getline(iss2, list_line2) && line2 < height - 10) {
                                        mvprintw(line2++, 4, "%s", list_line2.c_str());
                                    }
                                    
                                    // Input prompt
                                    mvprintw(height - 6, 2, "Enter game name to return: ");
                                    
                                    // Get game name
                                    echo();
                                    curs_set(1);
                                    char game_name2[256] = {0};
                                    getnstr(game_name2, 255);
                                    noecho();
                                    curs_set(0);
                                    
                                    if (strlen(game_name2) > 0) {
                                        // Send return command
                                        std::string return_response = send_command_and_get_response("RETURN " + std::string(game_name2));
                                        
                                        // Display result
                                        clear();
                                        box(stdscr, 0, 0);
                                        
                                        attron(A_BOLD);
                                        mvprintw(2, (width - 14) / 2, "RETURN RESULT");
                                        attroff(A_BOLD);
                                        
                                        // Parse response to show success/failure status
                                        if (return_response.find("success") != std::string::npos || 
                                            return_response.find("200") != std::string::npos) {
                                            // Success message
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(2)); // Green for success
                                            }
                                            mvprintw(4, 2, "SUCCESS: Game returned successfully!");
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(2));
                                            }
                                        } else {
                                            // Error message
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(3)); // Red for error
                                            }
                                            mvprintw(4, 2, "ERROR: Failed to return game.");
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(3));
                                            }
                                        }
                                        
                                        // Display full server response
                                        mvprintw(6, 2, "Server response:");
                                        int line_num2 = 7;
                                        std::istringstream resp_iss2(return_response);
                                        std::string resp_line2;
                                        
                                        while (std::getline(resp_iss2, resp_line2) && line_num2 < height - 4) {
                                            mvprintw(line_num2++, 4, "%s", resp_line2.c_str());
                                        }
                                    }
                                    
                                    // Wait for key press
                                    mvprintw(height - 2, 2, "Press any key to return to menu");
                                    refresh();
                                    getch();
                                    
                                    // Return to rent menu
                                    current_level = RENT_MENU;
                                    }
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
                                    {
                                    // Show rented games interface
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 16) / 2, "MY RENTED GAMES");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // Get list of rented games
                                    std::string my_rented_games = send_command_and_get_response("MYGAMES");
                                    
                                    // Display the list with proper formatting
                                    int my_line = 3;
                                    std::istringstream my_iss(my_rented_games);
                                    std::string my_list_line;
                                    
                                    while (std::getline(my_iss, my_list_line) && my_line < height - 4) {
                                        // If this looks like a status line, format it differently
                                        if (my_list_line.length() >= 3 && isdigit(my_list_line[0]) && 
                                            isdigit(my_list_line[1]) && isdigit(my_list_line[2])) {
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(2)); // Green for status
                                            }
                                            mvprintw(my_line++, 2, "Status: %s", my_list_line.c_str());
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(2));
                                            }
                                        } else if (!my_list_line.empty()) {
                                            // Add a bullet point to game names
                                            mvprintw(my_line++, 2, "• %s", my_list_line.c_str());
                                        }
                                    }
                                    
                                    // Wait for key press
                                    mvprintw(height - 2, 2, "Press any key to return to menu");
                                    refresh();
                                    getch();
                                    
                                    // Return to my games menu
                                    current_level = MYGAMES_MENU;
                                    }
                                    break;
                                    
                                case 1: // Rate a Game
                                    {
                                    // Show game rating interface
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 10) / 2, "RATE GAMES");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // First get rental history
                                    std::string rating_history = send_command_and_get_response("HISTORY");
                                    
                                    // Display instructions
                                    mvprintw(3, 2, "Your rental history (games you can rate):");
                                    
                                    // Display the history
                                    int rating_line = 5;
                                    std::istringstream rating_iss(rating_history);
                                    std::string rating_history_line;
                                    
                                    while (std::getline(rating_iss, rating_history_line) && rating_line < height - 10) {
                                        mvprintw(rating_line++, 4, "%s", rating_history_line.c_str());
                                    }
                                    
                                    // Input prompt for game name
                                    mvprintw(height - 8, 2, "Enter game name to rate: ");
                                    
                                    // Get game name
                                    echo();
                                    curs_set(1);
                                    char rating_game_name[256] = {0};
                                    getnstr(rating_game_name, 255);
                                    
                                    if (strlen(rating_game_name) > 0) {
                                        // Input prompt for rating
                                        mvprintw(height - 6, 2, "Enter rating (1-5): ");
                                        
                                        // Get rating
                                        char rating_str[2] = {0};
                                        getnstr(rating_str, 1);
                                        
                                        if (strlen(rating_str) > 0 && rating_str[0] >= '1' && rating_str[0] <= '5') {
                                            // Send rate command
                                            std::string rate_response = send_command_and_get_response(
                                                "RATE " + std::string(rating_game_name) + " " + rating_str);
                                            
                                            // Display result
                                            clear();
                                            box(stdscr, 0, 0);
                                            
                                            attron(A_BOLD);
                                            mvprintw(2, (width - 12) / 2, "RATING RESULT");
                                            attroff(A_BOLD);
                                            
                                            // Display full server response
                                            mvprintw(4, 2, "Server response:");
                                            int rate_line_num = 5;
                                            std::istringstream rate_resp_iss(rate_response);
                                            std::string rate_resp_line;
                                            
                                            while (std::getline(rate_resp_iss, rate_resp_line) && rate_line_num < height - 4) {
                                                mvprintw(rate_line_num++, 4, "%s", rate_resp_line.c_str());
                                            }
                                            
                                            // Wait for key press
                                            mvprintw(height - 2, 2, "Press any key to return to menu");
                                            refresh();
                                            getch();
                                        }
                                    }
                                    
                                    noecho();
                                    curs_set(0);
                                    
                                    // Return to my games menu
                                    current_level = MYGAMES_MENU;
                                    }
                                    break;
                                    
                                case 2: // View Recommendations
                                    {
                                    // Show recommendations interface
                                    clear();
                                    box(stdscr, 0, 0);
                                    
                                    // Title
                                    attron(A_BOLD);
                                    if (has_colors()) {
                                        attron(COLOR_PAIR(4)); // Yellow for title
                                    }
                                    mvprintw(1, (width - 17) / 2, "RECOMMENDATIONS");
                                    if (has_colors()) {
                                        attroff(COLOR_PAIR(4));
                                    }
                                    attroff(A_BOLD);
                                    
                                    // Get recommendations
                                    std::string my_recommendations = send_command_and_get_response("RECOMMEND");
                                    
                                    // Display the recommendations with proper formatting
                                    int rec_line = 3;
                                    std::istringstream my_rec_iss(my_recommendations);
                                    std::string my_rec_line;
                                    
                                    while (std::getline(my_rec_iss, my_rec_line) && rec_line < height - 4) {
                                        // Format response code differently
                                        if (my_rec_line.length() >= 3 && isdigit(my_rec_line[0]) && 
                                            isdigit(my_rec_line[1]) && isdigit(my_rec_line[2])) {
                                            if (has_colors()) {
                                                attron(COLOR_PAIR(2)); // Green for status
                                            }
                                            mvprintw(rec_line++, 2, "Status: %s", my_rec_line.c_str());
                                            if (has_colors()) {
                                                attroff(COLOR_PAIR(2));
                                            }
                                        } else if (!my_rec_line.empty()) {
                                            // Format game recommendations with bullet points
                                            if (my_rec_line[0] != '-' && !isdigit(my_rec_line[0])) {
                                                mvprintw(rec_line++, 2, "• %s", my_rec_line.c_str());
                                            } else {
                                                mvprintw(rec_line++, 2, "%s", my_rec_line.c_str());
                                            }
                                        }
                                    }
                                    
                                    // Wait for key press
                                    mvprintw(height - 2, 2, "Press any key to return to menu");
                                    refresh();
                                    getch();
                                    
                                    // Return to my games menu
                                    current_level = MYGAMES_MENU;
                                    }
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
        use_default_colors();  // This enables transparent background (-1)
        init_pair(1, COLOR_WHITE, COLOR_BLUE);     // For titles
        init_pair(2, COLOR_GREEN, -1);             // For success messages with transparent background
        init_pair(3, COLOR_RED, -1);               // For error messages with transparent background
        init_pair(4, COLOR_YELLOW, -1);            // For warnings/highlights with transparent background
        init_pair(5, 8, -1);                       // Grey for borders with transparent background
        
        // Set transparent background for the main screen
        // This allows the terminal's background to show through
        set_transparent_background(stdscr);
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