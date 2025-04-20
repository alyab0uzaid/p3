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
void login_form();
void signup_form();
void main_menu();
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
    
    mvwprintw(win, 1, 2, "Message");
    mvwprintw(win, 3, 2, "%s", message.c_str());
    mvwprintw(win, 8, 2, "Press any key to continue...");
    
    wrefresh(win);
    wgetch(win);
    
    delwin(win);
    refresh();
}

// Login form
void login_form() {
    clear();
    
    FIELD *fields[3];
    FORM *form;
    int ch;
    
    // Initialize fields
    fields[0] = new_field(1, 30, 4, 15, 0, 0);
    fields[1] = new_field(1, 30, 6, 15, 0, 0);
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
    mvprintw(4, 5, "Username:");
    mvprintw(6, 5, "Password:");
    mvprintw(10, 5, "Press F1 or Enter to submit, F2 to cancel");
    refresh();
    
    // Form navigation
    while((ch = getch()) != KEY_F(1) && ch != 10) { // 10 is Enter key
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
            case KEY_F(2):
                // Free form resources
                unpost_form(form);
                free_form(form);
                free_field(fields[0]);
                free_field(fields[1]);
                return;
            default:
                form_driver(form, ch);
                break;
        }
    }
    
    // Tell the form to finish editing
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
    display_message_box("Server response: " + user_response);
    
    std::string pass_response = send_command_and_get_response("PASS " + password_str);
    display_message_box("Server response: " + pass_response);
    
    // Check if login was successful
    if (pass_response.find("230") != std::string::npos) {
        is_authenticated = true;
        current_user = username_str;
    }
    
    // Free form resources
    unpost_form(form);
    free_form(form);
    free_field(fields[0]);
    free_field(fields[1]);
}

// Signup form
void signup_form() {
    clear();
    
    FIELD *fields[4];
    FORM *form;
    int ch;
    
    // Initialize fields
    fields[0] = new_field(1, 30, 4, 15, 0, 0);
    fields[1] = new_field(1, 30, 6, 15, 0, 0);
    fields[2] = new_field(1, 30, 8, 15, 0, 0);
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
    mvprintw(4, 5, "Username:");
    mvprintw(6, 5, "Password:");
    mvprintw(8, 5, "Confirm Password:");
    mvprintw(12, 5, "Press F1 or Enter to submit, F2 to cancel");
    refresh();
    
    // Form navigation
    while((ch = getch()) != KEY_F(1) && ch != 10) { // 10 is Enter key
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
            case KEY_F(2):
                // Free form resources
                unpost_form(form);
                free_form(form);
                free_field(fields[0]);
                free_field(fields[1]);
                free_field(fields[2]);
                return;
            default:
                form_driver(form, ch);
                break;
        }
    }
    
    // Tell the form to finish editing
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
        display_message_box("Passwords do not match.");
        
        // Free form resources
        unpost_form(form);
        free_form(form);
        free_field(fields[0]);
        free_field(fields[1]);
        free_field(fields[2]);
        return;
    }
    
    // Send signup command
    std::string signup_response = send_command_and_get_response("NEWUSER " + username_str);
    display_message_box("Server response: " + signup_response);
    
    if (signup_response.find("230") != std::string::npos) {
        // If successful, try to login with the new credentials
        std::string user_response = send_command_and_get_response("USER " + username_str);
        std::string pass_response = send_command_and_get_response("PASS " + password_str);
        
        if (pass_response.find("230") != std::string::npos) {
            is_authenticated = true;
            current_user = username_str;
            display_message_box("Login successful with new account.");
        } else {
            display_message_box("Account created, but login failed: " + pass_response);
        }
    }
    
    // Free form resources
    unpost_form(form);
    free_form(form);
    free_field(fields[0]);
    free_field(fields[1]);
    free_field(fields[2]);
}

// Main menu
void main_menu() {
    ITEM** items;
    MENU* menu;
    int n_choices, c;
    
    // Menu choices
    const char* choices[] = {
        "Login",
        "Signup",
        "Exit",
    };
    n_choices = ARRAY_SIZE(choices);
    
    // Create items
    items = (ITEM**)calloc(n_choices + 1, sizeof(ITEM*));
    for(int i = 0; i < n_choices; ++i) {
        items[i] = new_item(choices[i], "");
    }
    items[n_choices] = NULL;
    
    // Create menu
    menu = new_menu(items);
    
    // Set main window and sub window
    set_menu_win(menu, stdscr);
    set_menu_sub(menu, derwin(stdscr, n_choices, 40, 8, 20));
    set_menu_mark(menu, " * ");
    
    // Print a border and title
    box(stdscr, 0, 0);
    mvprintw(2, 2, "Game Rental System - Main Menu");
    mvprintw(20, 2, "F1 or Enter to select, q to exit");
    refresh();
    
    // Post the menu
    post_menu(menu);
    refresh();
    
    // Menu navigation
    while((c = getch()) != 'q') {
        switch(c) {
            case KEY_DOWN:
                menu_driver(menu, REQ_DOWN_ITEM);
                break;
            case KEY_UP:
                menu_driver(menu, REQ_UP_ITEM);
                break;
            case KEY_F(1): // Select option
            case 10:      // Enter key (ASCII 10)
                {
                    ITEM* cur = current_item(menu);
                    int index = item_index(cur);
                    
                    if (index == 0) { // Login
                        login_form();
                        if (is_authenticated) {
                            // Free menu resources
                            unpost_menu(menu);
                            for(int i = 0; i < n_choices; ++i)
                                free_item(items[i]);
                            free_menu(menu);
                            
                            // Go to command interface
                            command_interface();
                            return;
                        }
                    } else if (index == 1) { // Signup
                        signup_form();
                        if (is_authenticated) {
                            // Free menu resources
                            unpost_menu(menu);
                            for(int i = 0; i < n_choices; ++i)
                                free_item(items[i]);
                            free_menu(menu);
                            
                            // Go to command interface
                            command_interface();
                            return;
                        }
                    } else if (index == 2) { // Exit
                        // Free menu resources
                        unpost_menu(menu);
                        for(int i = 0; i < n_choices; ++i)
                            free_item(items[i]);
                        free_menu(menu);
                        return;
                    }
                    
                    // Redraw menu
                    clear();
                    box(stdscr, 0, 0);
                    mvprintw(2, 2, "Game Rental System - Main Menu");
                    mvprintw(20, 2, "F1 or Enter to select, q to exit");
                    post_menu(menu);
                    refresh();
                }
                break;
        }
    }
    
    // Free menu resources
    unpost_menu(menu);
    for(int i = 0; i < n_choices; ++i)
        free_item(items[i]);
    free_menu(menu);
}

// Command interface
void command_interface() {
    clear();
    
    // Create windows for command input and output
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    
    WINDOW* output_win = newwin(max_y - 5, max_x, 0, 0);
    WINDOW* input_win = newwin(3, max_x, max_y - 3, 0);
    scrollok(output_win, TRUE);
    
    // Draw borders
    box(output_win, 0, 0);
    box(input_win, 0, 0);
    
    // Add titles
    mvwprintw(output_win, 0, 2, "Server Output");
    mvwprintw(input_win, 0, 2, "Command Input (type 'BYE' to logout)");
    
    // Display welcome and help
    std::string help_response = send_command_and_get_response("HELP");
    mvwprintw(output_win, 1, 1, "Welcome, %s!", current_user.c_str());
    mvwprintw(output_win, 2, 1, "%s", help_response.c_str());
    
    wrefresh(output_win);
    wrefresh(input_win);
    
    // Command input loop
    char cmd_buf[256];
    int y_offset = 3; // Start output after welcome and help
    
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
        mvwprintw(input_win, 0, 2, "Command Input (type 'BYE' to logout)");
        wmove(input_win, 1, 1);
        wrefresh(input_win);
        
        // Handle exit command
        if (command == "BYE" || command == "bye") {
            send_command_and_get_response("BYE");
            break;
        }
        
        // Send command to server
        std::string response = send_command_and_get_response(command);
        
        // Display command and response
        mvwprintw(output_win, y_offset, 1, "> %s", command.c_str());
        y_offset++;
        
        // Handle multi-line responses
        std::istringstream iss(response);
        std::string line;
        while (std::getline(iss, line)) {
            // Check if we need to scroll
            if (y_offset >= max_y - 7) {
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
        wrefresh(input_win);
    }
    
    // Clean up windows
    delwin(output_win);
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
    
    // Connect to the server
    if (!connect_to_server(server_ip, server_port)) {
        endwin();
        std::cerr << "Failed to connect to server at " << server_ip << ":" << server_port << std::endl;
        cleanup_openssl();
        return 1;
    }
    
    // Show main menu
    main_menu();
    
    // Clean up and exit
    cleanup_connection();
    cleanup_openssl();
    endwin();
    
    return 0;
} 