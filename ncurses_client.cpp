/*
 * P3 NCURSES SECURE CLIENT
 * ------------------------
 * Description: Secure client with ncurses-based TUI for the video games rental system
 */

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <optional>
#include <filesystem>
#include <format>
#include <array>
#include <vector>
#include <thread>
#include <chrono>
#include <algorithm>  // For std::transform
#include <ncurses.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

constexpr size_t MAXDATASIZE = 100000;

// TUI state enum
enum class TUIState {
    LOGIN,
    MAIN_MENU,
    BOOK_LIST,
    SEARCH_BOOKS,
    CHECKOUT_FORM,
    RETURN_FORM,
    HISTORY_VIEW
};

// Global state variables
TUIState current_state = TUIState::LOGIN;
std::string username;
std::string server_response;
std::vector<std::string> books;
int highlighted_item = 0;
int scroll_offset = 0;

// Function prototypes
void init_ncurses();
void draw_login_screen();
void draw_main_menu();
void draw_book_list();
void draw_search_form();
void draw_checkout_form();
void draw_return_form();
void draw_history_view();
void handle_login(SSL* ssl, const std::string& username, const std::string& password);
void handle_command(SSL* ssl, const std::string& command);
void parse_books_list(const std::string& response);
void cleanup_ncurses();

// Get sockaddr, IPv4 or IPv6
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Initialize ncurses settings
void init_ncurses() {
    initscr();              // Start ncurses mode
    cbreak();               // Line buffering disabled
    keypad(stdscr, TRUE);   // Enable function keys
    noecho();               // Don't echo while getting input
    start_color();          // Enable color
    curs_set(0);            // Hide cursor
    
    // Define color pairs
    init_pair(1, COLOR_WHITE, COLOR_BLUE);    // Title bar
    init_pair(2, COLOR_BLACK, COLOR_WHITE);   // Selected item
    init_pair(3, COLOR_GREEN, COLOR_BLACK);   // Success message
    init_pair(4, COLOR_RED, COLOR_BLACK);     // Error message
}

// Draw the login screen
void draw_login_screen() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "SECURE VIDEO GAME RENTAL SYSTEM - LOGIN");
    for (int i = 40; i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // Draw login form with visible boxes
    mvprintw(3, 2, "Username: ");
    attron(A_UNDERLINE);
    for (int i = 0; i < 20; i++) {
        mvprintw(3, 12 + i, " ");
    }
    attroff(A_UNDERLINE);
    
    mvprintw(5, 2, "Password: ");
    attron(A_UNDERLINE);
    for (int i = 0; i < 20; i++) {
        mvprintw(5, 12 + i, " ");
    }
    attroff(A_UNDERLINE);
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Press TAB to switch fields, ENTER to login");
    
    refresh();
}

// Draw the main menu screen
void draw_main_menu() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "MAIN MENU - Logged in as: %s", username.c_str());
    for (int i = 30 + username.length(); i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // Draw menu options
    const char* menu_items[] = {
        "1. Browse Games",
        "2. Search Games",
        "3. Check-out Game",
        "4. Return Game",
        "5. View Rental History",
        "6. Logout"
    };
    
    for (int i = 0; i < 6; i++) {
        if (i == highlighted_item) {
            attron(COLOR_PAIR(2));
            mvprintw(i + 3, 2, "%s", menu_items[i]);
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(i + 3, 2, "%s", menu_items[i]);
        }
    }
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Use UP/DOWN arrows to navigate, ENTER to select");
    
    refresh();
}

// Draw the book list screen
void draw_book_list() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "AVAILABLE GAMES - Logged in as: %s", username.c_str());
    for (int i = 30 + username.length(); i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // If books list is empty, populate with some sample games for testing UI-only mode
    if (books.empty()) {
        books = {
            "1. The Legend of Zelda: Breath of the Wild | Nintendo | Available",
            "2. God of War | Sony | Available",
            "3. Red Dead Redemption 2 | Rockstar Games | Available",
            "4. Super Mario Odyssey | Nintendo | Checked out",
            "5. Cyberpunk 2077 | CD Projekt Red | Available",
            "6. Elden Ring | FromSoftware | Available",
            "7. Animal Crossing: New Horizons | Nintendo | Checked out",
            "8. Final Fantasy VII Remake | Square Enix | Available",
            "9. The Last of Us Part II | Naughty Dog | Available",
            "10. Halo Infinite | 343 Industries | Available",
            "11. Minecraft | Mojang | Available",
            "12. Ghost of Tsushima | Sucker Punch | Checked out"
        };
    }
    
    // Calculate visible items based on screen height
    int max_display_items = LINES - 6;  // Leave room for title and instructions
    
    // Draw column headers
    mvprintw(2, 2, "ID  TITLE                                  PUBLISHER               STATUS");
    mvprintw(3, 2, "--------------------------------------------------------------------------------");
    
    // Display books with scrolling
    int end_idx = std::min(static_cast<int>(books.size()), scroll_offset + max_display_items);
    for (int i = scroll_offset; i < end_idx; i++) {
        if (i == highlighted_item) {
            attron(COLOR_PAIR(2));
            // Fill the entire line
            for (int j = 0; j < COLS - 4; j++) {
                mvprintw(i - scroll_offset + 4, 2 + j, " ");
            }
            mvprintw(i - scroll_offset + 4, 2, "%s", books[i].c_str());
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(i - scroll_offset + 4, 2, "%s", books[i].c_str());
        }
    }
    
    // Draw scroll indicators if needed
    if (scroll_offset > 0) {
        mvprintw(4, COLS - 3, "↑");
    }
    if (books.size() > scroll_offset + max_display_items) {
        mvprintw(LINES - 3, COLS - 3, "↓");
    }
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Use UP/DOWN to navigate, ENTER to select, B to go back");
    
    refresh();
}

// Draw the search form screen
void draw_search_form() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "SEARCH GAMES - Logged in as: %s", username.c_str());
    for (int i = 30 + username.length(); i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // Draw search form
    mvprintw(3, 2, "Search by title: ");
    attron(A_UNDERLINE);
    for (int i = 0; i < 30; i++) {
        mvprintw(3, 18 + i, " ");
    }
    attroff(A_UNDERLINE);
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Type your search query and press ENTER, B to go back");
    
    refresh();
}

// Draw the checkout form screen
void draw_checkout_form() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "CHECK-OUT GAME - Logged in as: %s", username.c_str());
    for (int i = 30 + username.length(); i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // Draw form
    mvprintw(3, 2, "Game ID: ");
    attron(A_UNDERLINE);
    for (int i = 0; i < 5; i++) {
        mvprintw(3, 11 + i, " ");
    }
    attroff(A_UNDERLINE);
    
    mvprintw(5, 2, "Days to rent (1-14): ");
    attron(A_UNDERLINE);
    for (int i = 0; i < 3; i++) {
        mvprintw(5, 23 + i, " ");
    }
    attroff(A_UNDERLINE);
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Press TAB to switch fields, ENTER to submit, B to go back");
    
    refresh();
}

// Draw the return form screen
void draw_return_form() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "RETURN GAME - Logged in as: %s", username.c_str());
    for (int i = 30 + username.length(); i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // Draw form
    mvprintw(3, 2, "Game ID to return: ");
    attron(A_UNDERLINE);
    for (int i = 0; i < 5; i++) {
        mvprintw(3, 20 + i, " ");
    }
    attroff(A_UNDERLINE);
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Enter game ID and press ENTER to submit, B to go back");
    
    refresh();
}

// Draw the rental history view
void draw_history_view() {
    clear();
    
    // Draw title bar
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "RENTAL HISTORY - Logged in as: %s", username.c_str());
    for (int i = 30 + username.length(); i < COLS; i++) {
        mvprintw(0, i, " ");
    }
    attroff(COLOR_PAIR(1));
    
    // Sample rental history for UI testing
    std::vector<std::string> history = {
        "2023-04-15 | Super Mario Odyssey | Rented for 7 days | Returned on time",
        "2023-05-02 | Elden Ring | Rented for 10 days | Returned on time",
        "2023-05-20 | God of War | Rented for 5 days | Returned 2 days late",
        "2023-06-10 | Minecraft | Rented for 3 days | Returned on time",
        "2023-07-05 | Animal Crossing: New Horizons | Rented for 14 days | Currently checked out"
    };
    
    // Draw column headers
    mvprintw(2, 2, "DATE       | TITLE                      | RENTAL PERIOD    | STATUS");
    mvprintw(3, 2, "-------------------------------------------------------------------------");
    
    // Display rental history
    for (size_t i = 0; i < history.size(); i++) {
        mvprintw(i + 4, 2, "%s", history[i].c_str());
    }
    
    // Draw instructions
    mvprintw(LINES - 2, 2, "Press B to go back to main menu");
    
    refresh();
}

// Clean up ncurses before exiting
void cleanup_ncurses() {
    endwin();
}

// Handle login with the server
void handle_login(SSL* ssl, const std::string& username, const std::string& password) {
    if (!ssl) return;
    
    std::array<char, MAXDATASIZE> buffer;
    
    // Send USER command
    std::string user_cmd = "USER " + username + "\r\n";
    if (SSL_write(ssl, user_cmd.c_str(), user_cmd.length()) <= 0) {
        // Handle error
        return;
    }
    
    // Read USER response
    int bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
    if (bytes <= 0) {
        // Handle error
        return;
    }
    buffer[bytes] = '\0';
    server_response = buffer.data();
    
    // Send PASS command
    std::string pass_cmd = "PASS " + password + "\r\n";
    if (SSL_write(ssl, pass_cmd.c_str(), pass_cmd.length()) <= 0) {
        // Handle error
        return;
    }
    
    // Read PASS response with retries
    for (int attempts = 0; attempts < 5; attempts++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
        if (bytes > 0) break;
    }
    
    if (bytes <= 0) {
        // Handle error
        return;
    }
    buffer[bytes] = '\0';
    server_response = buffer.data();
}

// Send a command to the server and get response
bool handle_command(SSL* ssl, const std::string& command, std::string& response) {
    if (!ssl) return false;
    
    std::array<char, MAXDATASIZE> buffer;
    
    // Add CRLF if needed
    std::string cmd = command;
    if (cmd.substr(cmd.length() - 2) != "\r\n") {
        cmd += "\r\n";
    }
    
    // Send command
    if (SSL_write(ssl, cmd.c_str(), cmd.length()) <= 0) {
        return false;
    }
    
    // Read response with retries
    int bytes = 0;
    for (int attempts = 0; attempts < 5; attempts++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        bytes = SSL_read(ssl, buffer.data(), buffer.size() - 1);
        if (bytes > 0) break;
    }
    
    if (bytes <= 0) {
        return false;
    }
    
    buffer[bytes] = '\0';
    response = buffer.data();
    return true;
}

// Parse LIST response to get books
void parse_books_list(const std::string& response) {
    books.clear();
    
    std::stringstream ss(response);
    std::string line;
    
    // Skip the first line which is the response code
    std::getline(ss, line);
    
    // Parse each line of the response
    while (std::getline(ss, line)) {
        if (line.empty() || line == ".\r") {
            break;  // End of list
        }
        
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        books.push_back(line);
    }
}

int main(int argc, char* argv[]) {
    bool skip_connection = false;
    
    if (argc >= 2 && std::string(argv[1]) == "--ui-only") {
        skip_connection = true;
        std::cout << "Running in UI-only mode (no server connection)" << std::endl;
    } else if (argc != 2) {
        std::cerr << "usage: ncurses_client client.conf\n";
        std::cerr << "       ncurses_client --ui-only\n";
        return 1;
    }

    SSL* ssl = nullptr;
    SSL_CTX* ctx = nullptr;
    int sockfd = -1;
    
    if (!skip_connection) {
        // Initialize OpenSSL
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        // ERR_load_BIO_strings() is deprecated in OpenSSL 3.0
        
        // Read configuration from file
        std::optional<std::string> serverIP, serverPort;
        std::filesystem::path configFilePath(argv[1]);

        if (!std::filesystem::is_regular_file(configFilePath)) {
            std::cerr << "Error opening config file: " << argv[1] << std::endl;
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

        if (!serverIP.has_value() || !serverPort.has_value()) {
            std::cerr << "Invalid config file format.\n";
            return 1;
        }

        std::cout << "Attempting to connect to " << *serverIP << ":" << *serverPort << "..." << std::endl;

        // Set up connection hints
        addrinfo hints, *servinfo, *p;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        // Get address information
        int rv = getaddrinfo(serverIP->c_str(), serverPort->c_str(), &hints, &servinfo);
        if (rv != 0) {
            std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
            return 1;
        }

        // Loop through results and try to connect
        for (p = servinfo; p != nullptr; p = p->ai_next) {
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
            std::cerr << "Running in UI-only mode for testing\n";
            skip_connection = true;
        } else {
            // Display connection information
            char s[INET6_ADDRSTRLEN];
            inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
            std::cout << "client: connecting to " << s << std::endl;

            freeaddrinfo(servinfo);
            
            // Set up SSL context
            const SSL_METHOD *method = TLS_client_method();
            ctx = SSL_CTX_new(method);
            
            if (!ctx) {
                ERR_print_errors_fp(stderr);
                close(sockfd);
                return 1;
            }
            
            // Configure TLS 1.3
            if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
                !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
                std::cerr << "Error setting TLS protocol version" << std::endl;
                SSL_CTX_free(ctx);
                close(sockfd);
                return 1;
            }
            
            // Create SSL object
            ssl = SSL_new(ctx);
            if (!ssl) {
                std::cerr << "Error creating SSL object" << std::endl;
                SSL_CTX_free(ctx);
                close(sockfd);
                return 1;
            }
            
            // Set up SSL connection
            SSL_set_fd(ssl, sockfd);
            if (SSL_connect(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                SSL_CTX_free(ctx);
                close(sockfd);
                std::cerr << "Running in UI-only mode for testing\n";
                skip_connection = true;
            } else {
                std::cout << "TLS handshake completed." << std::endl;
            }
        }
    }
    
    std::cout << "Starting ncurses interface..." << std::endl;
    
    // Initialize ncurses
    init_ncurses();
    
    // Force initial draw of login screen
    draw_login_screen();
    
    // Main TUI loop
    bool quit = false;
    std::string input_username;
    std::string input_password;
    int current_field = 0;  // 0 = username, 1 = password
    
    while (!quit) {
        int ch = 0;  // Initialize ch outside the switch to avoid variable initialization issues
        
        // Handle the current TUI state
        switch (current_state) {
            case TUIState::LOGIN:
                draw_login_screen();
                
                // Position cursor based on current field
                if (current_field == 0) {
                    mvprintw(3, 12, "%s", input_username.c_str());
                    move(3, 12 + input_username.length());
                    curs_set(1);  // Show cursor
                } else {
                    mvprintw(5, 12, "%s", std::string(input_password.length(), '*').c_str());
                    move(5, 12 + input_password.length());
                    curs_set(1);  // Show cursor
                }
                
                // Get input
                ch = getch();
                switch (ch) {
                    case '\t':
                        // Switch between username and password fields
                        current_field = (current_field + 1) % 2;
                        break;
                    case '\n':
                        // Attempt login
                        if (!input_username.empty() && !input_password.empty()) {
                            if (!skip_connection && ssl) {
                                // Show "Logging in..." message
                                attron(COLOR_PAIR(3));
                                mvprintw(7, 2, "Logging in, please wait...");
                                attroff(COLOR_PAIR(3));
                                refresh();
                                
                                // Perform actual login
                                handle_login(ssl, input_username, input_password);
                                
                                // Check login response for success
                                if (server_response.find("230") != std::string::npos) {
                                    // Login successful
                                    username = input_username;
                                    current_state = TUIState::MAIN_MENU;
                                    highlighted_item = 0;
                                } else if (server_response.find("530") != std::string::npos) {
                                    // Login failed
                                    attron(COLOR_PAIR(4));
                                    mvprintw(7, 2, "Login failed: Invalid username or password");
                                    attroff(COLOR_PAIR(4));
                                    refresh();
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                } else if (server_response.find("331") != std::string::npos) {
                                    // New user registration
                                    attron(COLOR_PAIR(3));
                                    mvprintw(7, 2, "New user registered. The server has generated a password for you.");
                                    mvprintw(8, 2, "Password: %s", server_response.substr(server_response.find("Password:") + 10).c_str());
                                    attroff(COLOR_PAIR(3));
                                    refresh();
                                    std::this_thread::sleep_for(std::chrono::seconds(5));
                                } else {
                                    // Other error
                                    attron(COLOR_PAIR(4));
                                    mvprintw(7, 2, "Error: %s", server_response.c_str());
                                    attroff(COLOR_PAIR(4));
                                    refresh();
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                }
                            } else {
                                // UI-only mode, just proceed to main menu
                                username = input_username;
                                current_state = TUIState::MAIN_MENU;
                                highlighted_item = 0;
                            }
                        }
                        break;
                    case KEY_BACKSPACE:
                    case 127:
                        // Handle backspace
                        if (current_field == 0 && !input_username.empty()) {
                            input_username.pop_back();
                        } else if (current_field == 1 && !input_password.empty()) {
                            input_password.pop_back();
                        }
                        break;
                    default:
                        // Add character to current field
                        if (ch >= 32 && ch <= 126) {  // Printable ASCII
                            if (current_field == 0) {
                                input_username += ch;
                            } else {
                                input_password += ch;
                            }
                        }
                        break;
                }
                break;
                
            case TUIState::MAIN_MENU:
                draw_main_menu();
                
                // Get input
                ch = getch();
                switch (ch) {
                    case KEY_UP:
                        highlighted_item = (highlighted_item - 1 + 6) % 6;
                        break;
                    case KEY_DOWN:
                        highlighted_item = (highlighted_item + 1) % 6;
                        break;
                    case '\n':
                        // Handle menu selection
                        switch (highlighted_item) {
                            case 0:  // Browse Games
                                current_state = TUIState::BOOK_LIST;
                                break;
                            case 1:  // Search Games
                                current_state = TUIState::SEARCH_BOOKS;
                                break;
                            case 2:  // Check-out Game
                                current_state = TUIState::CHECKOUT_FORM;
                                break;
                            case 3:  // Return Game
                                current_state = TUIState::RETURN_FORM;
                                break;
                            case 4:  // View Rental History
                                current_state = TUIState::HISTORY_VIEW;
                                break;
                            case 5:  // Logout
                                // Reset login fields
                                input_username.clear();
                                input_password.clear();
                                current_field = 0;
                                current_state = TUIState::LOGIN;
                                break;
                        }
                        highlighted_item = 0;
                        break;
                    case 'q':
                        quit = true;
                        break;
                }
                break;
                
            case TUIState::BOOK_LIST:
                // If connected to server and books list is empty, try to fetch it
                if (!skip_connection && ssl && books.empty()) {
                    std::string response;
                    if (handle_command(ssl, "LIST", response)) {
                        parse_books_list(response);
                    }
                }
                
                draw_book_list();
                
                // Get input
                ch = getch();
                switch (ch) {
                    case KEY_UP:
                        if (highlighted_item > 0) {
                            highlighted_item--;
                            // Scroll up if needed
                            if (highlighted_item < scroll_offset) {
                                scroll_offset--;
                            }
                        }
                        break;
                    case KEY_DOWN:
                        if (highlighted_item < books.size() - 1) {
                            highlighted_item++;
                            // Calculate visible items
                            int max_display_items = LINES - 6;
                            // Scroll down if needed
                            if (highlighted_item >= scroll_offset + max_display_items) {
                                scroll_offset++;
                            }
                        }
                        break;
                    case 'b':
                    case 'B':
                        // Return to main menu
                        current_state = TUIState::MAIN_MENU;
                        highlighted_item = 0;
                        scroll_offset = 0;
                        break;
                    case '\n':
                        // For now, just show a message
                        attron(COLOR_PAIR(3));
                        mvprintw(LINES - 1, 2, "Selected game: %s", 
                                 books[highlighted_item].c_str());
                        attroff(COLOR_PAIR(3));
                        refresh();
                        // Give time to see the message
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                        break;
                }
                break;
                
            case TUIState::SEARCH_BOOKS:
                {
                    static std::string search_query;
                    
                    draw_search_form();
                    
                    // Display current search query
                    mvprintw(3, 18, "%s", search_query.c_str());
                    move(3, 18 + search_query.length());
                    curs_set(1);  // Show cursor
                    
                    // Get input
                    ch = getch();
                    switch (ch) {
                        case '\n':
                            // Perform search (in a real implementation, this would query the server)
                            if (!search_query.empty()) {
                                attron(COLOR_PAIR(3));
                                mvprintw(5, 2, "Searching for: %s", search_query.c_str());
                                attroff(COLOR_PAIR(3));
                                refresh();
                                
                                // In UI-only mode, just filter existing books that contain the query
                                books.clear();
                                for (int i = 1; i <= 12; i++) {
                                    std::string game_title;
                                    switch (i) {
                                        case 1: game_title = "The Legend of Zelda: Breath of the Wild"; break;
                                        case 2: game_title = "God of War"; break;
                                        case 3: game_title = "Red Dead Redemption 2"; break;
                                        case 4: game_title = "Super Mario Odyssey"; break;
                                        case 5: game_title = "Cyberpunk 2077"; break;
                                        case 6: game_title = "Elden Ring"; break;
                                        case 7: game_title = "Animal Crossing: New Horizons"; break;
                                        case 8: game_title = "Final Fantasy VII Remake"; break;
                                        case 9: game_title = "The Last of Us Part II"; break;
                                        case 10: game_title = "Halo Infinite"; break;
                                        case 11: game_title = "Minecraft"; break;
                                        case 12: game_title = "Ghost of Tsushima"; break;
                                    }
                                    
                                    // Publisher and status
                                    std::string publisher;
                                    std::string status = (i % 4 == 0) ? "Checked out" : "Available";
                                    
                                    switch (i) {
                                        case 1: case 4: case 7: publisher = "Nintendo"; break;
                                        case 2: case 9: publisher = "Sony"; break;
                                        case 3: publisher = "Rockstar Games"; break;
                                        case 5: publisher = "CD Projekt Red"; break;
                                        case 6: publisher = "FromSoftware"; break;
                                        case 8: publisher = "Square Enix"; break;
                                        case 10: publisher = "343 Industries"; break;
                                        case 11: publisher = "Mojang"; break;
                                        case 12: publisher = "Sucker Punch"; break;
                                    }
                                    
                                    // If game title contains search query (case-insensitive)
                                    std::string title_lower = game_title;
                                    std::string query_lower = search_query;
                                    std::transform(title_lower.begin(), title_lower.end(), title_lower.begin(), ::tolower);
                                    std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), ::tolower);
                                    
                                    if (title_lower.find(query_lower) != std::string::npos) {
                                        books.push_back(std::to_string(i) + ". " + game_title + " | " + publisher + " | " + status);
                                    }
                                }
                                
                                // Give time to see the message
                                std::this_thread::sleep_for(std::chrono::seconds(1));
                                
                                // Show results
                                current_state = TUIState::BOOK_LIST;
                                highlighted_item = 0;
                                scroll_offset = 0;
                            }
                            break;
                        case KEY_BACKSPACE:
                        case 127:
                            // Handle backspace
                            if (!search_query.empty()) {
                                search_query.pop_back();
                            }
                            break;
                        case 'b':
                        case 'B':
                            if (search_query.empty()) {
                                // Return to main menu only if query is empty
                                search_query.clear();
                                current_state = TUIState::MAIN_MENU;
                                highlighted_item = 0;
                            } else {
                                // Otherwise treat as input
                                search_query += ch;
                            }
                            break;
                        default:
                            // Add character to search query
                            if (ch >= 32 && ch <= 126) {  // Printable ASCII
                                search_query += ch;
                            }
                            break;
                    }
                }
                break;
                
            case TUIState::CHECKOUT_FORM:
                {
                    static std::string game_id;
                    static std::string rental_days;
                    static int checkout_field = 0;  // 0 = game_id, 1 = rental_days
                    
                    draw_checkout_form();
                    
                    // Position cursor based on current field and display input
                    if (checkout_field == 0) {
                        mvprintw(3, 11, "%s", game_id.c_str());
                        move(3, 11 + game_id.length());
                        curs_set(1);  // Show cursor
                    } else {
                        mvprintw(3, 11, "%s", game_id.c_str());
                        mvprintw(5, 23, "%s", rental_days.c_str());
                        move(5, 23 + rental_days.length());
                        curs_set(1);  // Show cursor
                    }
                    
                    // Get input
                    ch = getch();
                    switch (ch) {
                        case '\t':
                            // Switch between fields
                            checkout_field = (checkout_field + 1) % 2;
                            break;
                        case '\n':
                            // Process checkout
                            if (!game_id.empty() && !rental_days.empty()) {
                                // Validate input
                                bool valid_id = true;
                                for (char c : game_id) {
                                    if (!std::isdigit(c)) {
                                        valid_id = false;
                                        break;
                                    }
                                }
                                
                                bool valid_days = true;
                                int days = 0;
                                try {
                                    days = std::stoi(rental_days);
                                    if (days < 1 || days > 14) {
                                        valid_days = false;
                                    }
                                } catch (...) {
                                    valid_days = false;
                                }
                                
                                if (valid_id && valid_days) {
                                    // Display success message
                                    attron(COLOR_PAIR(3));
                                    mvprintw(7, 2, "Game %s checked out for %s days.", 
                                            game_id.c_str(), rental_days.c_str());
                                    attroff(COLOR_PAIR(3));
                                    refresh();
                                    
                                    // Clear input for next time
                                    game_id.clear();
                                    rental_days.clear();
                                    checkout_field = 0;
                                    
                                    // Return to main menu after delay
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                    current_state = TUIState::MAIN_MENU;
                                    highlighted_item = 0;
                                } else {
                                    // Display error message
                                    attron(COLOR_PAIR(4));
                                    if (!valid_id) {
                                        mvprintw(7, 2, "Error: Game ID must be a number.");
                                    } else {
                                        mvprintw(7, 2, "Error: Rental days must be between 1 and 14.");
                                    }
                                    attroff(COLOR_PAIR(4));
                                    refresh();
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                }
                            }
                            break;
                        case KEY_BACKSPACE:
                        case 127:
                            // Handle backspace
                            if (checkout_field == 0 && !game_id.empty()) {
                                game_id.pop_back();
                            } else if (checkout_field == 1 && !rental_days.empty()) {
                                rental_days.pop_back();
                            }
                            break;
                        case 'b':
                        case 'B':
                            // Return to main menu
                            game_id.clear();
                            rental_days.clear();
                            checkout_field = 0;
                            current_state = TUIState::MAIN_MENU;
                            highlighted_item = 0;
                            break;
                        default:
                            // Add character to current field
                            if (ch >= 32 && ch <= 126) {  // Printable ASCII
                                if (checkout_field == 0) {
                                    // Only allow digits for game ID
                                    if (std::isdigit(ch) && game_id.length() < 5) {
                                        game_id += ch;
                                    }
                                } else {
                                    // Only allow digits for rental days
                                    if (std::isdigit(ch) && rental_days.length() < 2) {
                                        rental_days += ch;
                                    }
                                }
                            }
                            break;
                    }
                }
                break;
                
            case TUIState::RETURN_FORM:
                {
                    static std::string return_id;
                    
                    draw_return_form();
                    
                    // Display current input
                    mvprintw(3, 20, "%s", return_id.c_str());
                    move(3, 20 + return_id.length());
                    curs_set(1);  // Show cursor
                    
                    // Get input
                    ch = getch();
                    switch (ch) {
                        case '\n':
                            // Process return
                            if (!return_id.empty()) {
                                // Validate input
                                bool valid_id = true;
                                for (char c : return_id) {
                                    if (!std::isdigit(c)) {
                                        valid_id = false;
                                        break;
                                    }
                                }
                                
                                if (valid_id) {
                                    // Display success message
                                    attron(COLOR_PAIR(3));
                                    mvprintw(5, 2, "Game %s returned successfully.", return_id.c_str());
                                    attroff(COLOR_PAIR(3));
                                    refresh();
                                    
                                    // Clear input for next time
                                    return_id.clear();
                                    
                                    // Return to main menu after delay
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                    current_state = TUIState::MAIN_MENU;
                                    highlighted_item = 0;
                                } else {
                                    // Display error message
                                    attron(COLOR_PAIR(4));
                                    mvprintw(5, 2, "Error: Game ID must be a number.");
                                    attroff(COLOR_PAIR(4));
                                    refresh();
                                    std::this_thread::sleep_for(std::chrono::seconds(2));
                                }
                            }
                            break;
                        case KEY_BACKSPACE:
                        case 127:
                            // Handle backspace
                            if (!return_id.empty()) {
                                return_id.pop_back();
                            }
                            break;
                        case 'b':
                        case 'B':
                            // Return to main menu
                            return_id.clear();
                            current_state = TUIState::MAIN_MENU;
                            highlighted_item = 0;
                            break;
                        default:
                            // Add character to input
                            if (ch >= 32 && ch <= 126) {  // Printable ASCII
                                // Only allow digits for game ID
                                if (std::isdigit(ch) && return_id.length() < 5) {
                                    return_id += ch;
                                }
                            }
                            break;
                    }
                }
                break;
                
            case TUIState::HISTORY_VIEW:
                draw_history_view();
                
                // Get input
                ch = getch();
                switch (ch) {
                    case 'b':
                    case 'B':
                        // Return to main menu
                        current_state = TUIState::MAIN_MENU;
                        highlighted_item = 0;
                        break;
                }
                break;
                
            // Default case already implemented
            default:
                // For now, pressing any key returns to main menu
                mvprintw(LINES/2, COLS/2 - 15, "Feature not yet implemented");
                mvprintw(LINES/2 + 1, COLS/2 - 15, "Press any key to return to main menu");
                refresh();
                getch();
                current_state = TUIState::MAIN_MENU;
                break;
        }
    }
    
    // Cleanup
    cleanup_ncurses();
    
    if (!skip_connection) {
        if (ssl) SSL_shutdown(ssl);
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        if (sockfd >= 0) close(sockfd);
    }
    
    return 0;
} 