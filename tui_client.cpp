/*
 * P3 SECURE CLIENT WITH NCURSES TUI
 * ----------------------------
 * Simple ncurses-based TUI client for the secure video game rental system
 * Date: 04/20/2025
 */

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <ncurses.h>
#include <menu.h>
#include <form.h>
#include <panel.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

// Global variables
SSL_CTX* ssl_ctx = nullptr;
SSL* ssl = nullptr;
int sockfd = -1;
bool connected = false;
bool authenticated = false;
std::string current_user;

// Configuration
std::string server_host;
std::string server_port;

// UI components
WINDOW* status_win = nullptr;
WINDOW* input_win = nullptr;
WINDOW* output_win = nullptr;

// Function prototypes
bool read_config(const std::string& config_file);
bool init_openssl();
void cleanup_openssl();
bool connect_to_server();
void disconnect_from_server();
bool send_command(const std::string& command, std::string& response);
void cleanup_ui();
void init_ui();
void update_status(const std::string& message);
void show_login_screen();
void show_main_menu();
void handle_browse_mode();
void handle_rent_mode();
void handle_my_games_mode();
void show_message(const std::string& message);
std::string get_string_input(const std::string& prompt);
int get_int_input(const std::string& prompt);
int menu_selection(const std::vector<std::string>& menu_items);

// Read configuration from client.conf
bool read_config(const std::string& config_file) {
    std::ifstream conf(config_file);
    if (!conf.is_open()) {
        std::cerr << "Error opening configuration file: " << config_file << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(conf, line)) {
        if (line.substr(0, 5) == "HOST=") {
            server_host = line.substr(5);
        } else if (line.substr(0, 5) == "PORT=") {
            server_port = line.substr(5);
        } else if (line.substr(0, 10) == "SERVER_IP=") {
            server_host = line.substr(10);
        } else if (line.substr(0, 12) == "SERVER_PORT=") {
            server_port = line.substr(12);
        }
    }
    
    if (server_host.empty() || server_port.empty()) {
        std::cerr << "Missing server host or port in configuration file" << std::endl;
        return false;
    }
    
    return true;
}

// Initialize OpenSSL
bool init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    // Create SSL context with TLS client method
    const SSL_METHOD* method = TLS_client_method();
    ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    // Set TLS 1.3 as the only allowed protocol version
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        std::cerr << "Failed to set minimum TLS version" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    if (SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        std::cerr << "Failed to set maximum TLS version" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    return true;
}

// Clean up OpenSSL resources
void cleanup_openssl() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }
    
    EVP_cleanup();
    ERR_free_strings();
}

// Connect to the server
bool connect_to_server() {
    struct addrinfo hints, *servinfo, *p;
    int rv;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((rv = getaddrinfo(server_host.c_str(), server_port.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return false;
    }
    
    // Loop through all the results and connect to the first we can
    for(p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }
        
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        
        break;
    }
    
    if (p == nullptr) {
        std::cerr << "client: failed to connect" << std::endl;
        return false;
    }
    
    freeaddrinfo(servinfo);
    
    // Create a new SSL structure
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        std::cerr << "Failed to create SSL structure" << std::endl;
        ERR_print_errors_fp(stderr);
        close(sockfd);
        return false;
    }
    
    // Attach the socket descriptor to the SSL structure
    SSL_set_fd(ssl, sockfd);
    
    // Perform the SSL handshake
    if (SSL_connect(ssl) != 1) {
        std::cerr << "SSL connect failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        close(sockfd);
        return false;
    }
    
    connected = true;
    return true;
}

// Disconnect from server
void disconnect_from_server() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    
    if (sockfd != -1) {
        close(sockfd);
        sockfd = -1;
    }
    
    connected = false;
    authenticated = false;
}

// Send command to server and get response
bool send_command(const std::string& command, std::string& response) {
    if (!connected || !ssl) {
        return false;
    }
    
    // Send command with \n terminator
    std::string cmd_with_newline = command + "\n";
    int bytes = SSL_write(ssl, cmd_with_newline.c_str(), cmd_with_newline.length());
    if (bytes <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes);
        std::cerr << "SSL write error: " << ssl_error << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    // Read response
    char buffer[4096];
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes);
        std::cerr << "SSL read error: " << ssl_error << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    buffer[bytes] = '\0';
    response = buffer;
    
    // Remove trailing newline if present
    if (!response.empty() && response.back() == '\n') {
        response.pop_back();
    }
    
    return true;
}

// Initialize ncurses UI
void init_ui() {
    // Initialize ncurses
    initscr();
    start_color();
    cbreak();
    noecho();
    curs_set(0);  // Hide cursor
    keypad(stdscr, TRUE);  // Enable keyboard input
    
    // Get screen dimensions
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    
    // Calculate window dimensions
    int status_height = 3;
    int input_height = 3;
    int output_height = max_y - status_height - input_height;
    
    // Create windows
    status_win = newwin(status_height, max_x, 0, 0);
    output_win = newwin(output_height, max_x, status_height, 0);
    input_win = newwin(input_height, max_x, max_y - input_height, 0);
    
    // Enable keyboard input for all windows
    keypad(status_win, TRUE);
    keypad(output_win, TRUE);
    keypad(input_win, TRUE);
    
    // Add borders
    box(status_win, 0, 0);
    box(output_win, 0, 0);
    box(input_win, 0, 0);
    
    // Set up status window
    wbkgd(status_win, A_REVERSE);
    mvwprintw(status_win, 1, 2, "Secure Video Game Rental System");
    
    // Initial refresh
    refresh();
    wrefresh(status_win);
    wrefresh(output_win);
    wrefresh(input_win);
    
    // Set initial status
    update_status("Initializing...");
}

// Clean up ncurses UI
void cleanup_ui() {
    // Delete windows
    delwin(status_win);
    delwin(output_win);
    delwin(input_win);
    
    // End ncurses
    endwin();
}

// Update status message
void update_status(const std::string& message) {
    werase(status_win);
    box(status_win, 0, 0);
    wbkgd(status_win, A_REVERSE);
    mvwprintw(status_win, 1, 2, "Secure Video Game Rental System");
    mvwprintw(status_win, 1, COLS - message.length() - 3, "%s", message.c_str());
    wrefresh(status_win);
}

// Show message in output window
void show_message(const std::string& message) {
    // Enable scrolling for output window
    scrollok(output_win, TRUE);
    
    // Add message to output window
    waddstr(output_win, (message + "\n").c_str());
    
    // Refresh window
    wrefresh(output_win);
}

// Get string input from user
std::string get_string_input(const std::string& prompt) {
    // Show prompt in input window
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "%s: ", prompt.c_str());
    wrefresh(input_win);
    
    // Enable echo and cursor for input
    echo();
    curs_set(1);
    
    // Get input
    char input[256];
    wgetnstr(input_win, input, sizeof(input) - 1);
    
    // Disable echo and cursor
    noecho();
    curs_set(0);
    
    // Clear input window
    werase(input_win);
    box(input_win, 0, 0);
    wrefresh(input_win);
    
    return std::string(input);
}

// Get integer input from user
int get_int_input(const std::string& prompt) {
    while (true) {
        std::string input = get_string_input(prompt);
        if (input.empty()) {
            return 0;
        }
        
        try {
            return std::stoi(input);
        } catch (const std::exception& e) {
            werase(input_win);
            box(input_win, 0, 0);
            mvwprintw(input_win, 1, 2, "Invalid number. Try again.");
            wrefresh(input_win);
            // Wait a moment so the user can see the error
            napms(1500);
        }
    }
}

// Login screen
void show_login_screen() {
    werase(output_win);
    show_message("=== Secure Video Game Rental System ===");
    show_message("Please login to continue.");
    
    update_status("Login Screen");
    
    std::string username = get_string_input("Username");
    
    // Send USER command
    std::string response;
    if (!send_command("USER " + username, response)) {
        show_message("Error sending USER command");
        return;
    }
    
    show_message("Server: " + response);
    
    // Check if this is a new user
    if (response.find("New user created") != std::string::npos) {
        // Extract password from response
        size_t pos = response.find("Your password is: ");
        if (pos != std::string::npos) {
            std::string password = response.substr(pos + 18);
            show_message("Please remember this password for future logins.");
            show_message("The connection will now close. Please restart the client to login.");
            
            // Wait for user to press a key
            mvwprintw(input_win, 1, 1, "Press any key to continue...");
            wrefresh(input_win);
            wgetch(input_win);
            
            disconnect_from_server();
            return;
        }
    } else {
        // Get password for existing user
        std::string password = get_string_input("Password");
        
        // Send PASS command
        if (!send_command("PASS " + password, response)) {
            show_message("Error sending PASS command");
            return;
        }
        
        show_message("Server: " + response);
        
        // Check if authentication was successful
        if (response.find("Authentication successful") != std::string::npos) {
            authenticated = true;
            current_user = username;
            update_status("Logged in as: " + current_user);
            
            // Display success message
            show_message("Login successful! Welcome, " + current_user);
            
            // Wait for user to press a key
            mvwprintw(input_win, 1, 1, "Press any key to continue...");
            wrefresh(input_win);
            wgetch(input_win);
        } else {
            // Authentication failed
            show_message("Login failed. Please try again.");
            
            // Wait for user to press a key
            mvwprintw(input_win, 1, 1, "Press any key to continue...");
            wrefresh(input_win);
            wgetch(input_win);
            
            // Check if connection needs to be closed
            if (response.find("too many invalid attempts") != std::string::npos) {
                disconnect_from_server();
            }
        }
    }
}

// Handle BROWSE mode
void handle_browse_mode() {
    std::string response;
    
    // Enter BROWSE mode
    if (!send_command("BROWSE", response)) {
        show_message("Error sending BROWSE command");
        return;
    }
    
    show_message("Server: " + response);
    update_status("BROWSE Mode | User: " + current_user);
    
    bool browsing = true;
    while (browsing && connected) {
        werase(output_win);
        show_message("=== BROWSE Mode ===");
        
        std::vector<std::string> menu_items = {
            "LIST - Show all games",
            "LIST platform - Show games by platform",
            "LIST genre - Show games by genre",
            "LIST rating - Show games by rating",
            "SEARCH - Search for games",
            "SHOW - Show game details",
            "Return to main menu"
        };
        
        int choice = menu_selection(menu_items);
        
        switch (choice) {
            case 6: // Return to main menu
                browsing = false;
                break;
                
            case 0: {
                // LIST all games
                if (!send_command("LIST", response)) {
                    show_message("Error sending LIST command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 1: {
                // LIST platform
                if (!send_command("LIST platform", response)) {
                    show_message("Error sending LIST platform command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 2: {
                // LIST genre
                if (!send_command("LIST genre", response)) {
                    show_message("Error sending LIST genre command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 3: {
                // LIST rating
                if (!send_command("LIST rating", response)) {
                    show_message("Error sending LIST rating command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 4: {
                // SEARCH
                std::string filter = get_string_input("Enter filter (title, platform, genre, esrb)");
                std::string keyword = get_string_input("Enter search keyword");
                
                if (!send_command("SEARCH " + filter + " " + keyword, response)) {
                    show_message("Error sending SEARCH command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 5: {
                // SHOW
                int game_id = get_int_input("Enter game ID");
                std::string show_cmd = "SHOW " + std::to_string(game_id);
                
                if (!send_command(show_cmd, response)) {
                    show_message("Error sending SHOW command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            default:
                browsing = false; // User pressed F1 or other key
                break;
        }
    }
}

// Handle RENT mode
void handle_rent_mode() {
    std::string response;
    
    // Enter RENT mode
    if (!send_command("RENT", response)) {
        show_message("Error sending RENT command");
        return;
    }
    
    show_message("Server: " + response);
    update_status("RENT Mode | User: " + current_user);
    
    bool renting = true;
    while (renting && connected) {
        werase(output_win);
        show_message("=== RENT Mode ===");
        
        std::vector<std::string> menu_items = {
            "CHECKOUT - Checkout a game",
            "RETURN - Return a game",
            "Return to main menu"
        };
        
        int choice = menu_selection(menu_items);
        
        switch (choice) {
            case 2: // Return to main menu
                renting = false;
                break;
                
            case 0: {
                // CHECKOUT
                int game_id = get_int_input("Enter game ID to checkout");
                
                if (!send_command("CHECKOUT " + std::to_string(game_id), response)) {
                    show_message("Error sending CHECKOUT command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 1: {
                // RETURN
                int game_id = get_int_input("Enter game ID to return");
                
                if (!send_command("RETURN " + std::to_string(game_id), response)) {
                    show_message("Error sending RETURN command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            default:
                renting = false; // User pressed F1 or other key
                break;
        }
    }
}

// Handle MYGAMES mode
void handle_my_games_mode() {
    std::string response;
    
    // Enter MYGAMES mode
    if (!send_command("MYGAMES", response)) {
        show_message("Error sending MYGAMES command");
        return;
    }
    
    show_message("Server: " + response);
    update_status("MYGAMES Mode | User: " + current_user);
    
    bool my_games = true;
    while (my_games && connected) {
        werase(output_win);
        show_message("=== MYGAMES Mode ===");
        
        std::vector<std::string> menu_items = {
            "HISTORY - View rental history",
            "RECOMMEND - Get game recommendations",
            "RATE - Rate a game",
            "Return to main menu"
        };
        
        int choice = menu_selection(menu_items);
        
        switch (choice) {
            case 3: // Return to main menu
                my_games = false;
                break;
                
            case 0: {
                // HISTORY
                if (!send_command("HISTORY", response)) {
                    show_message("Error sending HISTORY command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 1: {
                // RECOMMEND
                std::string filter = get_string_input("Enter filter (platform, genre) or leave empty");
                std::string cmd = "RECOMMEND";
                if (!filter.empty()) {
                    cmd += " " + filter;
                }
                
                if (!send_command(cmd, response)) {
                    show_message("Error sending RECOMMEND command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            case 2: {
                // RATE
                int game_id = get_int_input("Enter game ID");
                int rating = -1;
                while (rating < 1 || rating > 10) {
                    rating = get_int_input("Enter rating (1-10)");
                    if (rating < 1 || rating > 10) {
                        show_message("Rating must be between 1 and 10");
                    }
                }
                
                if (!send_command("RATE " + std::to_string(game_id) + " " + std::to_string(rating), response)) {
                    show_message("Error sending RATE command");
                    continue;
                }
                
                werase(output_win);
                show_message(response);
                mvwprintw(input_win, 1, 1, "Press any key to continue...");
                wrefresh(input_win);
                wgetch(input_win);
                break;
            }
                
            default:
                my_games = false; // User pressed F1 or other key
                break;
        }
    }
}

// Helper function for arrow-key based menu
int menu_selection(const std::vector<std::string>& menu_items) {
    int selection = 0;
    int key;
    int max_items = menu_items.size();
    
    // Enable keyboard input for output window
    keypad(output_win, TRUE);
    
    // Draw initial menu
    werase(output_win);
    for (size_t i = 0; i < menu_items.size(); i++) {
        if (i == selection) {
            wattron(output_win, A_REVERSE);
            mvwprintw(output_win, i+1, 1, "> %s", menu_items[i].c_str());
            wattroff(output_win, A_REVERSE);
        } else {
            mvwprintw(output_win, i+1, 1, "  %s", menu_items[i].c_str());
        }
    }
    wrefresh(output_win);
    
    // Clear input window and show navigation help
    werase(input_win);
    mvwprintw(input_win, 1, 1, "Use UP/DOWN arrows and ENTER to select");
    wrefresh(input_win);
    
    // Main input loop
    while (1) {
        key = wgetch(output_win);
        
        switch(key) {
            case KEY_UP:
                selection = (selection - 1 + max_items) % max_items;
                break;
            case KEY_DOWN:
                selection = (selection + 1) % max_items;
                break;
            case 10: // Enter key
                // Disable keypad for output window when done
                keypad(output_win, FALSE);
                return selection;
            case 'q': // Allow q to exit
            case 27:  // ESC key
                // Disable keypad for output window when done
                keypad(output_win, FALSE);
                return -1;
        }
        
        // Redraw menu
        werase(output_win);
        for (size_t i = 0; i < menu_items.size(); i++) {
            if (i == selection) {
                wattron(output_win, A_REVERSE);
                mvwprintw(output_win, i+1, 1, "> %s", menu_items[i].c_str());
                wattroff(output_win, A_REVERSE);
            } else {
                mvwprintw(output_win, i+1, 1, "  %s", menu_items[i].c_str());
            }
        }
        wrefresh(output_win);
    }
    
    // Should never reach here
    return -1;
}

// Main menu
void show_main_menu() {
    bool running = true;
    
    while (running && connected && authenticated) {
        werase(output_win);
        show_message("=== Video Game Rental System ===");
        
        std::vector<std::string> menu_items = {
            "BROWSE - Browse the game catalog",
            "RENT - Checkout or return games",
            "MYGAMES - View history and recommendations",
            "Logout and exit"
        };
        
        update_status("Main Menu | User: " + current_user);
        
        int choice = menu_selection(menu_items);
        
        switch (choice) {
            case 4: { // Logout and exit
                // LOGOUT
                std::string response;
                send_command("BYE", response);
                show_message("Server: " + response);
                running = false;
                break;
            }
                
            case 0:
                // BROWSE
                handle_browse_mode();
                break;
                
            case 1:
                // RENT
                handle_rent_mode();
                break;
                
            case 2:
                // MYGAMES
                handle_my_games_mode();
                break;
                
                
            default:
                running = false; // User pressed F1 or some other key
                break;
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }
    
    // Read configuration
    if (!read_config(argv[1])) {
        std::cerr << "Failed to read configuration" << std::endl;
        return 1;
    }
    
    // Initialize OpenSSL
    if (!init_openssl()) {
        std::cerr << "Failed to initialize OpenSSL" << std::endl;
        return 1;
    }
    
    // Initialize UI
    init_ui();
    
    try {
        // Main application loop
        bool running = true;
        while (running) {
            // Connect to server if not connected
            if (!connected) {
                update_status("Connecting to " + server_host + ":" + server_port);
                if (!connect_to_server()) {
                    show_message("Failed to connect to server");
                    running = false;
                    continue;
                }
                show_message("Connected to server");
            }
            
            // Show login screen if not authenticated
            if (!authenticated) {
                show_login_screen();
                if (!authenticated && !connected) {
                    // If we're not authenticated and not connected, connection was closed
                    running = false;
                    continue;
                }
            }
            
            // Show main menu if authenticated
            if (authenticated) {
                show_main_menu();
            }
            
            // If we reach here after main menu, we should exit
            running = false;
        }
    } catch (const std::exception& e) {
        cleanup_ui();
        std::cerr << "Error: " << e.what() << std::endl;
        disconnect_from_server();
        cleanup_openssl();
        return 1;
    }
    
    // Clean up
    cleanup_ui();
    disconnect_from_server();
    cleanup_openssl();
    
    return 0;
} 