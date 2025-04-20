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
bool login_form();
void signup_form();
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

// Signup form
void signup_form() {
    clear();
    
    // Create a border and title
    int height, width;
    getmaxyx(stdscr, height, width);
    box(stdscr, 0, 0);
    
    // Title
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(2, (width - 20) / 2, "Game Rental System");
    attroff(A_BOLD | A_UNDERLINE);
    mvprintw(4, (width - 15) / 2, "Registration Form");
    
    FIELD *fields[4];
    FORM *form;
    int ch;
    
    // Initialize fields
    fields[0] = new_field(1, 30, 8, (width - 30) / 2, 0, 0);
    fields[1] = new_field(1, 30, 10, (width - 30) / 2, 0, 0);
    fields[2] = new_field(1, 30, 12, (width - 30) / 2, 0, 0);
    fields[3] = NULL;
    
    // Set field options
    set_field_back(fields[0], A_UNDERLINE);
    set_field_back(fields[1], A_UNDERLINE);
    set_field_back(fields[2], A_UNDERLINE);
    field_opts_off(fields[1], O_PUBLIC); // Password field - don't show
    field_opts_off(fields[2], O_PUBLIC); // Confirm password field - don't show
    
    // Create the form
    form = new_form(fields);
    
    // Post the form
    post_form(form);
    
    // Labels
    mvprintw(8, (width - 30) / 2 - 18, "New Username:");
    mvprintw(10, (width - 30) / 2 - 18, "New Password:");
    mvprintw(12, (width - 30) / 2 - 18, "Confirm Password:");
    mvprintw(height - 4, 2, "Press F1 or Enter to submit");
    mvprintw(height - 3, 2, "Press F2 to cancel and return to login");
    refresh();
    
    // Form navigation
    bool done = false;
    while(!done) {
        ch = getch();
        
        if (ch == KEY_F(1) || ch == 10) { // F1 or Enter key
            // Process the form
            form_driver(form, REQ_VALIDATION);
            
            // Get field values
            char* username = field_buffer(fields[0], 0);
            char* password = field_buffer(fields[1], 0);
            char* confirm = field_buffer(fields[2], 0);
            
            // Trim whitespace
            std::string username_str(username);
            std::string password_str(password);
            std::string confirm_str(confirm);
            username_str.erase(username_str.find_last_not_of(" \n\r\t") + 1);
            password_str.erase(password_str.find_last_not_of(" \n\r\t") + 1);
            confirm_str.erase(confirm_str.find_last_not_of(" \n\r\t") + 1);
            
            // Check if passwords match
            if (password_str != confirm_str) {
                display_message_box("Passwords do not match. Please try again.");
                continue; // Go back to form input
            }
            
            // Send signup command
            std::string signup_response = send_command_and_get_response("NEWUSER " + username_str);
            
            if (signup_response.find("230") != std::string::npos) {
                display_message_box("Account created successfully! Please login with your new credentials.");
            } else {
                display_message_box("Account creation failed: " + signup_response);
            }
            
            // Free form resources
            unpost_form(form);
            free_form(form);
            free_field(fields[0]);
            free_field(fields[1]);
            free_field(fields[2]);
            done = true;
        }
        else if (ch == KEY_F(2)) {
            // Free form resources
            unpost_form(form);
            free_form(form);
            free_field(fields[0]);
            free_field(fields[1]);
            free_field(fields[2]);
            done = true;
        }
        else {
            // Handle normal form navigation
            switch(ch) {
                case KEY_DOWN:
                    form_driver(form, REQ_NEXT_FIELD);
                    form_driver(form, REQ_END_LINE);
                    break;
                case KEY_UP:
                    form_driver(form, REQ_PREV_FIELD);
                    form_driver(form, REQ_END_LINE);
                    break;
                case KEY_BACKSPACE:
                case 127:
                    form_driver(form, REQ_DEL_PREV);
                    break;
                default:
                    form_driver(form, ch);
                    break;
            }
        }
    }
}

// Login form
bool login_form() {
    clear();
    
    // Create a border and title
    int height, width;
    getmaxyx(stdscr, height, width);
    box(stdscr, 0, 0);
    
    // Title
    attron(A_BOLD | A_UNDERLINE);
    mvprintw(2, (width - 20) / 2, "Game Rental System");
    attroff(A_BOLD | A_UNDERLINE);
    mvprintw(4, (width - 10) / 2, "Login Form");
    
    FIELD *fields[3];
    FORM *form;
    int ch;
    
    // Initialize fields
    fields[0] = new_field(1, 30, 8, (width - 30) / 2, 0, 0);
    fields[1] = new_field(1, 30, 10, (width - 30) / 2, 0, 0);
    fields[2] = NULL;
    
    // Set field options
    set_field_back(fields[0], A_UNDERLINE);
    set_field_back(fields[1], A_UNDERLINE);
    field_opts_off(fields[1], O_PUBLIC); // Password field - don't show
    
    // Create the form
    form = new_form(fields);
    
    // Post the form
    post_form(form);
    
    // Labels
    mvprintw(8, (width - 30) / 2 - 10, "Username:");
    mvprintw(10, (width - 30) / 2 - 10, "Password:");
    mvprintw(height - 4, 2, "Press F1 or Enter to submit");
    mvprintw(height - 3, 2, "Press F2 to go to signup form");
    mvprintw(height - 2, 2, "Press F10 to exit");
    refresh();
    
    // Form navigation
    bool done = false;
    bool result = false;
    
    while(!done) {
        ch = getch();
        
        if (ch == KEY_F(10)) {
            // Exit
            unpost_form(form);
            free_form(form);
            free_field(fields[0]);
            free_field(fields[1]);
            return false;
        }
        else if (ch == KEY_F(2)) {
            // Free form resources
            unpost_form(form);
            free_form(form);
            free_field(fields[0]);
            free_field(fields[1]);
            
            // Go to signup form
            signup_form();
            
            // Return to login form
            return false;
        }
        else if (ch == KEY_F(1) || ch == 10) { // F1 or Enter key
            // Process form submission
            form_driver(form, REQ_VALIDATION);
            
            // Get field values
            char* username = field_buffer(fields[0], 0);
            char* password = field_buffer(fields[1], 0);
            
            // Trim whitespace
            std::string username_str(username);
            std::string password_str(password);
            username_str.erase(username_str.find_last_not_of(" \n\r\t") + 1);
            password_str.erase(password_str.find_last_not_of(" \n\r\t") + 1);
            
            // Send login commands
            std::string user_response = send_command_and_get_response("USER " + username_str);
            
            // Check if user exists
            if (user_response.find("430") != std::string::npos) {
                // User doesn't exist
                display_message_box("User not found. Would you like to sign up?");
                
                // Free form resources
                unpost_form(form);
                free_form(form);
                free_field(fields[0]);
                free_field(fields[1]);
                
                // Go to signup form
                signup_form();
                
                // Return to login form
                return false;
            }
            
            std::string pass_response = send_command_and_get_response("PASS " + password_str);
            
            // Check if login was successful
            if (pass_response.find("230") != std::string::npos) {
                is_authenticated = true;
                current_user = username_str;
                
                // Free form resources
                unpost_form(form);
                free_form(form);
                free_field(fields[0]);
                free_field(fields[1]);
                
                // Login successful
                return true;
            } else {
                display_message_box("Login failed: " + pass_response);
            }
        }
        else {
            // Handle normal form navigation
            switch(ch) {
                case KEY_DOWN:
                    form_driver(form, REQ_NEXT_FIELD);
                    form_driver(form, REQ_END_LINE);
                    break;
                case KEY_UP:
                    form_driver(form, REQ_PREV_FIELD);
                    form_driver(form, REQ_END_LINE);
                    break;
                case KEY_BACKSPACE:
                case 127:
                    form_driver(form, REQ_DEL_PREV);
                    break;
                default:
                    form_driver(form, ch);
                    break;
            }
        }
    }
    
    // If we get here and the form is still active, free it
    unpost_form(form);
    free_form(form);
    free_field(fields[0]);
    free_field(fields[1]);
    
    return result;  // Return whether login was successful
}

// Command interface - improved visual appearance
void command_interface() {
    clear();
    
    // Create windows for command input and output
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    
    WINDOW* header_win = newwin(3, max_x, 0, 0);
    WINDOW* output_win = newwin(max_y - 8, max_x, 3, 0);
    WINDOW* status_win = newwin(2, max_x, max_y - 5, 0);
    WINDOW* input_win = newwin(3, max_x, max_y - 3, 0);
    
    scrollok(output_win, TRUE);
    
    // Draw borders
    box(header_win, 0, 0);
    box(output_win, 0, 0);
    box(status_win, 0, 0);
    box(input_win, 0, 0);
    
    // Add titles with highlighting
    wattron(header_win, A_BOLD);
    mvwprintw(header_win, 1, max_x/2 - 15, "Game Rental System Terminal");
    wattroff(header_win, A_BOLD);
    
    wattron(output_win, A_BOLD);
    mvwprintw(output_win, 0, 2, " Server Output ");
    wattroff(output_win, A_BOLD);
    
    wattron(status_win, A_BOLD);
    mvwprintw(status_win, 0, 2, " Status ");
    wattroff(status_win, A_BOLD);
    
    wattron(input_win, A_BOLD);
    mvwprintw(input_win, 0, 2, " Command Input (type 'BYE' to logout) ");
    wattroff(input_win, A_BOLD);
    
    // Display welcome message in header
    mvwprintw(header_win, 1, 2, "User: %s", current_user.c_str());
    
    // Display status information
    mvwprintw(status_win, 1, 2, "Connected to server - Type HELP for available commands");
    
    // Get and display initial help
    std::string help_response = send_command_and_get_response("HELP");
    mvwprintw(output_win, 1, 1, "Welcome, %s!", current_user.c_str());
    
    // Print help response with proper formatting
    int y = 2;
    std::istringstream help_stream(help_response);
    std::string line;
    while (std::getline(help_stream, line) && y < max_y - 10) {
        mvwprintw(output_win, y, 1, "%s", line.c_str());
        y++;
    }
    
    // Refresh all windows
    wrefresh(header_win);
    wrefresh(output_win);
    wrefresh(status_win);
    wrefresh(input_win);
    
    // Command input loop
    char cmd_buf[256];
    int y_offset = y + 1; // Start output after welcome and help
    
    wmove(input_win, 1, 1);
    wrefresh(input_win);
    
    while (true) {
        // Get command from user
        echo();
        wgetstr(input_win, cmd_buf);
        noecho();
        
        std::string command(cmd_buf);
        
        // Clear input window for next command
        wclear(input_win);
        box(input_win, 0, 0);
        wattron(input_win, A_BOLD);
        mvwprintw(input_win, 0, 2, " Command Input (type 'BYE' to logout) ");
        wattroff(input_win, A_BOLD);
        wmove(input_win, 1, 1);
        wrefresh(input_win);
        
        // Handle exit command
        if (command == "BYE" || command == "bye") {
            send_command_and_get_response("BYE");
            break;
        }
        
        // Update status based on command
        wclear(status_win);
        box(status_win, 0, 0);
        wattron(status_win, A_BOLD);
        mvwprintw(status_win, 0, 2, " Status ");
        wattroff(status_win, A_BOLD);
        
        if (command == "BROWSE" || command == "browse") {
            mvwprintw(status_win, 1, 2, "MODE: BROWSE - View and search the game catalog");
        } else if (command == "RENT" || command == "rent") {
            mvwprintw(status_win, 1, 2, "MODE: RENT - Check out and return games");
        } else if (command == "MYGAMES" || command == "mygames") {
            mvwprintw(status_win, 1, 2, "MODE: MYGAMES - View history and recommendations");
        } else {
            mvwprintw(status_win, 1, 2, "Processing command: %s", command.c_str());
        }
        wrefresh(status_win);
        
        // Send command to server
        std::string response = send_command_and_get_response(command);
        
        // Display command with highlight
        wattron(output_win, A_BOLD | A_REVERSE);
        mvwprintw(output_win, y_offset, 1, "> %s", command.c_str());
        wattroff(output_win, A_BOLD | A_REVERSE);
        y_offset++;
        
        // Handle multi-line responses
        std::istringstream iss(response);
        std::string line;
        while (std::getline(iss, line)) {
            // Check if we need to scroll
            if (y_offset >= max_y - 10) {
                // Scroll content up
                wscrl(output_win, 5);
                y_offset -= 5;
            }
            
            mvwprintw(output_win, y_offset, 1, "%s", line.c_str());
            y_offset++;
        }
        y_offset++; // Extra line between commands
        
        // Refresh windows
        wrefresh(output_win);
    }
    
    // Clean up windows
    delwin(header_win);
    delwin(output_win);
    delwin(status_win);
    delwin(input_win);
    
    is_authenticated = false;
    current_user = "";
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
    
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    
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
    
    // Show login form directly (instead of main menu)
    // If login is successful, show command interface
    bool login_success = false;
    
    while (!login_success) {
        login_success = login_form();
        if (!login_success && !is_connected) {
            // User chose to exit
            break;
        }
    }
    
    if (login_success) {
        command_interface();
    }
    
    // Clean up and exit
    cleanup_connection();
    cleanup_openssl();
    endwin();
    
    return 0;
} 