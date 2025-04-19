/*
 * P3 SECURE SERVER
 * ---------------
 * Based on P1 sample by Thoshitha Gamage
 * Updated for P3 security requirements
 * Date: 04/18/2025
 * License: MIT License
 * Description: This is a secure video game rental server using TLS 1.3 for CS447 Spring 2025 P3.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>
#include <array>
#include <filesystem>
#include <format>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <mutex>
#include <cstdlib> // for getcwd
#include <climits> // for PATH_MAX
#include <cerrno>  // for errno codes

// OpenSSL headers for TLS support
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#define BACKLOG 10
#define MAXDATASIZE 100

// Global SSL context
SSL_CTX* ssl_ctx = nullptr;

// Initialize OpenSSL and create SSL context
bool init_openssl() {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    // Create SSL context with TLS 1.3
    const SSL_METHOD* method = TLS_server_method();
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
    
    // Configure the cipher suites for TLS 1.3
    if (SSL_CTX_set_ciphersuites(ssl_ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
        std::cerr << "Failed to set cipher suites" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "p3server.crt", SSL_FILETYPE_PEM) != 1) {
        std::cerr << "Failed to load certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "p3server.key", SSL_FILETYPE_PEM) != 1) {
        std::cerr << "Failed to load private key" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    // Verify private key matches the certificate
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        std::cerr << "Private key does not match the certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    std::cout << "OpenSSL initialized with TLS 1.3" << std::endl;
    return true;
}

// Clean up OpenSSL resources
void cleanup_openssl() {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }
    
    EVP_cleanup();
    ERR_free_strings();
}

// Base64 encoding function
std::string base64_encode(const unsigned char* data, size_t length) {
    std::cout << "base64_encode: Encoding " << length << " bytes" << std::endl;
    
    BIO* b64 = BIO_new(BIO_f_base64());
    // Set flags to disable newlines in the output
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    // Write the data to be encoded
    BIO_write(b64, data, length);
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    // Copy to a std::string, ensuring we don't include any trailing null bytes
    std::string result(bptr->data, bptr->length);
    
    BIO_free_all(b64);
    
    std::cout << "base64_encode: Result length: " << result.length() << " bytes" << std::endl;
    return result;
}

// Base64 decoding function
std::vector<unsigned char> base64_decode(const std::string& encoded_data) {
    std::cout << "base64_decode: Decoding string of length " << encoded_data.length() << std::endl;
    
    // Create BIO for base64 decoding with NO_NL flag to disable newlines
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    BIO* bmem = BIO_new_mem_buf(encoded_data.c_str(), encoded_data.length());
    bmem = BIO_push(b64, bmem);
    
    std::vector<unsigned char> result(encoded_data.length());
    int decoded_size = BIO_read(bmem, result.data(), encoded_data.length());
    
    if (decoded_size <= 0) {
        std::cerr << "base64_decode: Failed to decode data" << std::endl;
        ERR_print_errors_fp(stderr);
    }
    
    result.resize(decoded_size > 0 ? decoded_size : 0);
    
    BIO_free_all(bmem);
    
    std::cout << "base64_decode: Decoded size: " << result.size() << " bytes" << std::endl;
    return result;
}

// Wrapper for SSL connection
struct SSLConnection {
    SSL* ssl;
    int socket;
    
    SSLConnection(int sock) : ssl(nullptr), socket(sock) {
        ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to create SSL structure");
        }
        
        SSL_set_fd(ssl, socket);
    }
    
    ~SSLConnection() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        close(socket);
    }
    
    // Perform SSL handshake
    bool accept() {
        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            int err = SSL_get_error(ssl, ret);
            std::cerr << "SSL accept error: " << err << std::endl;
            ERR_print_errors_fp(stderr);
            return false;
        }
        return true;
    }
    
    // Read data from SSL connection
    int read(void* buf, int num) {
        return SSL_read(ssl, buf, num);
    }
    
    // Write data to SSL connection
    int write(const void* buf, int num) {
        return SSL_write(ssl, buf, num);
    }
    
    // Write a string response with proper line ending
    int write_response(const std::string& response) {
        std::string full_response = response + "\r\n";
        std::cout << "Sending response: " << response << std::endl;
        int result = SSL_write(ssl, full_response.c_str(), full_response.length());
        return result;
    }

    // Write a response in a format compatible with OpenSSL s_client
    // This method is ineffective with the openssl s_client tool - use the direct SSL_write instead
    int write_multiline_response(const std::string& response) {
        // CRITICAL FIX: Ensure we actually have a response to send
        if (response.empty()) {
            std::cerr << "ERROR: Trying to send empty response" << std::endl;
            // Send a fallback response so client isn't waiting forever
            std::string fallback = "200 OK\r\n";
            return SSL_write(ssl, fallback.c_str(), fallback.length());
        }
        
        // Format with explicit newlines and extra padding to force display
        std::string formatted_response = response;
        
        // Handle newlines 
        if (formatted_response.find('\n') != std::string::npos) {
            // Replace all \n with explicit \r\n if not already
            size_t pos = 0;
            while ((pos = formatted_response.find('\n', pos)) != std::string::npos) {
                if (pos == 0 || formatted_response[pos-1] != '\r') {
                    formatted_response.replace(pos, 1, "\r\n");
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
        }
        
        // Ensure the response ends with CRLF
        if (formatted_response.size() < 2 || 
            formatted_response.substr(formatted_response.size() - 2) != "\r\n") {
            formatted_response += "\r\n";
        }
        
        // Add a dot-terminator to signal end-of-message for SMTP-like protocols
        formatted_response += ".\r\n";
        
        std::cout << "Raw message to send:" << std::endl;
        for (size_t i = 0; i < formatted_response.size(); i++) {
            char c = formatted_response[i];
            if (c == '\r') std::cout << "<CR>";
            else if (c == '\n') std::cout << "<LF>" << std::endl;
            else std::cout << c;
        }
        std::cout << std::endl;
        
        // Try sending the entire response at once first
        int result = SSL_write(ssl, formatted_response.c_str(), formatted_response.length());
        
        if (result > 0) {
            std::cout << "Successfully sent entire response: " << result << " bytes" << std::endl;
            return result;
        }
        
        // If that failed, try the chunked approach
        std::cout << "Failed to send entire response, trying chunked approach" << std::endl;
        
        const int CHUNK_SIZE = 128; // Smaller chunks
        const char* data = formatted_response.c_str();
        int remaining = formatted_response.length();
        int total_sent = 0;
        
        while (remaining > 0) {
            int to_send = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
            int sent = SSL_write(ssl, data + total_sent, to_send);
            
            if (sent <= 0) {
                int err = SSL_get_error(ssl, sent);
                std::cerr << "SSL write error: " << err << std::endl;
                ERR_print_errors_fp(stderr);
                return sent;
            }
            
            total_sent += sent;
            remaining -= sent;
            
            std::cout << "Sent chunk: " << sent << " bytes, " << remaining << " remaining" << std::endl;
            
            // Larger delay between chunks
            usleep(50000); // 50ms
        }
        
        std::cout << "Successfully sent all chunks: " << total_sent << " bytes" << std::endl;
        return total_sent;
    }
};

// Keeps track of a user's checkout or return event.
struct RentalRecord {
    int gameId;
    std::string action; // "CHECKOUT" or "RETURN"
    std::string timestamp;
};

// Maps each user to a list of their rental actions.
static std::unordered_map<std::string, std::vector<RentalRecord>> userRentalHistory;
static std::mutex rentalMutex;

// Stores cumulative rating info (sum of ratings and total count).
struct RatingData {
    int totalRating = 0;
    int numRatings = 0;
};

static std::unordered_map<int, RatingData> globalRatings;
static std::unordered_map<std::string, std::unordered_map<int,int>> userRatings;
static std::mutex ratingMutex;

// Structure to store user credentials
struct UserCredential {
    std::string username;
    std::string salt;       // Base64 encoded
    std::string hash;       // Base64 encoded
    int failedAttempts;     // Count of consecutive failed login attempts
};

// Global map to store credentials in memory
static std::unordered_map<std::string, UserCredential> userCredentials;
static std::mutex credentialMutex;

struct Game {
    int id;
    std::string title;
    std::string platform;
    std::string genre;
    int year;
    std::string esrb;
    bool available;
    int copies;
};

// Creates a timestamp string for logs.
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Cleanup
void sigchld_handler(int s) {
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    errno = saved_errno;
}

// Picks IPv4 or IPv6 address.
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Logs a message with a timestamp.
void logEvent(const std::string& msg) {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << "] " << msg << std::endl;
}

std::string getPortFromConfig(const std::string& fileName) {
    std::filesystem::path p(fileName);
    if (!std::filesystem::is_regular_file(p)) {
        std::cerr << std::format("Error opening configuration file: {}\n", fileName);
        return "";
    }
    std::ifstream cf(fileName);
    std::string line;
    while (std::getline(cf, line)) {
        std::string_view sv(line);
        if (sv.substr(0, 5) == "PORT=") {
            return std::string(sv.substr(5));
        }
    }
    return "";
}

// Loads games from games.db.
std::vector<Game> loadGamesFromFile(const std::string &fileName) {
    std::vector<Game> games;
    std::ifstream file(fileName);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file: " << fileName << std::endl;
        return games;
    }
    std::string line;
    int lineNumber = 0;
    while (std::getline(file, line)) {
        lineNumber++;
        if (lineNumber == 1) {
            continue; // skip header
        }
        std::stringstream ss(line);
        std::string id, title, platform, genre, year, esrb, available, copies;
        if (!std::getline(ss, id, ';') ||
            !std::getline(ss, title, ';') ||
            !std::getline(ss, platform, ';') ||
            !std::getline(ss, genre, ';') ||
            !std::getline(ss, year, ';') ||
            !std::getline(ss, esrb, ';') ||
            !std::getline(ss, available, ';') ||
            !std::getline(ss, copies, ';')) {
            std::cerr << "Warning: malformed line " << lineNumber << ": " << line << std::endl;
            continue;
        }
        try {
            Game g;
            g.id = std::stoi(id);
            g.title = title;
            g.platform = platform;
            g.genre = genre;
            g.year = std::stoi(year);
            g.esrb = esrb;
            g.available = (available == "True");
            g.copies = std::stoi(copies);
            games.push_back(g);
        } catch(...) {
            std::cerr << "Error: invalid format in line " << lineNumber << ": " << line << std::endl;
        }
    }
    return games;
}

//HELP
std::string handleHelp(bool browseMode, bool rentMode, bool myGamesMode) {
    std::ostringstream out;
    out << "200 HELP\n";
    out << "-------------------------------------------\n";
    if (!browseMode && !rentMode && !myGamesMode) {
        out << "USER <username>\n";
        out << "PASS <password>\n";
        out << "HELP\n";
        out << "BROWSE\n";
        out << "RENT\n";
        out << "MYGAMES\n";
        out << "BYE\n\n";
        out << "COMMANDS INSIDE BROWSE MODE:\n";
        out << "  LIST [filter]\n";
        out << "  SEARCH <filter> <keyword>\n";
        out << "  SHOW <game_id> [availability]\n\n";
        out << "COMMANDS INSIDE RENT MODE:\n";
        out << "  CHECKOUT <game_id>\n";
        out << "  RETURN <game_id>\n\n";
        out << "COMMANDS INSIDE MYGAMES MODE:\n";
        out << "  HISTORY\n";
        out << "  RECOMMEND [platform|genre]\n";
        out << "  RATE <game_id> <rating>\n";
    }
    else if (browseMode) {
        out << "[BROWSE MODE COMMANDS]\n";
        out << "LIST [filter]\n";
        out << "SEARCH <filter> <keyword>\n";
        out << "SHOW <game_id> [availability]\n";
        out << "RENT\n";
        out << "MYGAMES\n";
        out << "HELP\n";
        out << "BYE\n";
    }
    else if (rentMode) {
        out << "[RENT MODE COMMANDS]\n";
        out << "CHECKOUT <game_id>\n";
        out << "RETURN <game_id>\n";
        out << "BROWSE\n";
        out << "MYGAMES\n";
        out << "HELP\n";
        out << "BYE\n";
    }
    else if (myGamesMode) {
        out << "[MYGAMES MODE COMMANDS]\n";
        out << "HISTORY\n";
        out << "RECOMMEND [platform|genre]\n";
        out << "RATE <game_id> <rating>\n";
        out << "BROWSE\n";
        out << "RENT\n";
        out << "HELP\n";
        out << "BYE\n";
    }
    out << "-------------------------------------------\n";
    return out.str();
}

//LIST
std::string handleList(const std::vector<Game> &games, const std::string &filterType) {
    // If no filter, list everything or 304 if empty.
    if (filterType.empty()) {
        if (games.empty()) {
            return "304 No video games available.";
        }
        std::ostringstream resp;
        resp << "250 List of available games\n";
        resp << "---------------------------------------\n";
        for (auto &gm : games) {
            double avg = 0.0;
            bool hasRatings = false;
            if (globalRatings.count(gm.id) && globalRatings[gm.id].numRatings > 0) {
                hasRatings = true;
                avg = (double)globalRatings[gm.id].totalRating / globalRatings[gm.id].numRatings;
            }
            std::ostringstream ratingStr;
            if (hasRatings) {
                ratingStr << std::fixed << std::setprecision(1) << avg;
            } else {
                ratingStr << "-";
            }
            resp << "ID: " << gm.id << " | " << gm.title << " (" << gm.year << ") | Rating: "
                 << ratingStr.str() << "/10\n";
            resp << "   Platform: " << gm.platform << "\n";
            resp << "   Genre: " << gm.genre << "\n";
            resp << "   ESRB: " << gm.esrb << "\n";
            resp << "   Available: " << (gm.available ? "Yes" : "No") << "\n";
            resp << "   Copies: " << gm.copies << "\n\n";
        }
        return resp.str();
    }
    // If filter is "title","platform","genre"
    if (filterType == "title" || filterType == "platform" || filterType == "genre") {
        std::unordered_map<std::string,int> seen;
        for (auto &g : games) {
            std::string val;
            if (filterType == "title") val = g.title;
            else if (filterType == "platform") val = g.platform;
            else val = g.genre;
            seen[val]++;
        }
        std::ostringstream resp;
        resp << "250 List of " << filterType << "s\n";
        resp << "---------------------------------------\n";
        for (auto &pair : seen) {
            resp << pair.first << "\n";
        }
        return resp.str();
    }
    // If filter is "rating"
    if (filterType == "rating") {
        if (games.empty()) {
            return "304 No video games available.";
        }
        std::vector<std::pair<double, Game>> rated;
        for (auto &gm : games) {
            double avg = 0.0;
            if (globalRatings.count(gm.id) && globalRatings[gm.id].numRatings > 0) {
                avg = (double)globalRatings[gm.id].totalRating / globalRatings[gm.id].numRatings;
            }
            rated.push_back(std::make_pair(avg, gm));
        }
        std::sort(rated.begin(), rated.end(), [](auto &a, auto &b){
            return a.first > b.first;
        });
        std::ostringstream resp;
        resp << "250 List of games sorted by rating\n";
        resp << "---------------------------------------\n";
        for (auto &r : rated) {
            double avg = r.first;
            auto &gm = r.second;
            if (globalRatings[gm.id].numRatings == 0) {
                resp << "ID: " << gm.id << " | " << gm.title << " (" << gm.year << ") | Rating: -/10\n";
            } else {
                resp << std::fixed << std::setprecision(1);
                resp << "ID: " << gm.id << " | " << gm.title << " (" << gm.year << ") | Rating: " << avg << "/10\n";
            }
        }
        return resp.str();
    }
    return "400 BAD REQUEST - Invalid filter type.";
}

//SEARCH
std::string handleSearch(const std::vector<Game> &games,
                         const std::string &filterType,
                         const std::string &filterValue) {
    std::ostringstream resp;
    resp << "250 Search results\n";
    resp << "---------------------------------------\n";
    int count = 0;
    for (auto &gm : games) {
        bool match = false;
        if (filterType=="title") {
            if (gm.title.find(filterValue) != std::string::npos) match = true;
        } else if (filterType=="platform") {
            if (gm.platform == filterValue) match = true;
        } else if (filterType=="genre") {
            if (gm.genre == filterValue) match = true;
        } else if (filterType=="esrb") {
            if (gm.esrb == filterValue) match = true;
        } else {
            return "400 BAD REQUEST - Invalid search filter.";
        }
        if (match) {
            double avg = 0.0;
            bool hasRatings = false;
            if (globalRatings.count(gm.id) && globalRatings[gm.id].numRatings>0) {
                hasRatings = true;
                avg = (double)globalRatings[gm.id].totalRating / globalRatings[gm.id].numRatings;
            }
            std::ostringstream ratingStr;
            if (hasRatings) {
                ratingStr << std::fixed << std::setprecision(1) << avg;
            } else {
                ratingStr << "-";
            }
            resp << "ID: " << gm.id << " | " << gm.title << " (" << gm.year << ") | Rating: "
                 << ratingStr.str() << "/10\n";
            resp << "   Platform: " << gm.platform << "\n";
            resp << "   Genre: " << gm.genre << "\n";
            resp << "   ESRB: " << gm.esrb << "\n";
            resp << "   Available: " << (gm.available ? "Yes" : "No") << "\n";
            resp << "   Copies: " << gm.copies << "\n";
            resp << "---------------------------------------\n";
            count++;
        }
    }
    if (count == 0) {
        return "304 No games matching your search.";
    }
    return resp.str();
}

//SHOW
std::string handleShow(const std::vector<Game> &games, const std::string &cmdLine) {
    std::istringstream ss(cmdLine);
    std::string cmd, idStr, availFlag;
    ss >> cmd >> idStr >> availFlag;
    int gameId;
    try {
        gameId = std::stoi(idStr);
    } catch(...) {
        return "400 BAD REQUEST - Invalid game ID";
    }
    for (auto &gm : games) {
        if (gm.id == gameId) {
            if (availFlag=="availability") {
                std::ostringstream out;
                out << "250 Game availability\n";
                out << "---------------------------------------\n";
                out << "Game ID: " << gm.id << " | " << gm.title << "\n";
                out << "Available: " << (gm.available ? "Yes" : "No") << "\n";
                out << "Copies left: " << gm.copies << "\n";
                out << "---------------------------------------\n";
                return out.str();
            } else {
                double avg = 0.0;
                int n = 0;
                if (globalRatings.count(gm.id) && globalRatings[gm.id].numRatings>0) {
                    avg = (double)globalRatings[gm.id].totalRating / globalRatings[gm.id].numRatings;
                    n = globalRatings[gm.id].numRatings;
                }
                std::ostringstream out;
                out << "250 Game details\n";
                out << "---------------------------------------\n";
                if (n==0) {
                    out << "ID: " << gm.id << " | " << gm.title
                        << " (" << gm.year << ") | Rating: -/10\n";
                } else {
                    out << std::fixed << std::setprecision(1);
                    out << "ID: " << gm.id << " | " << gm.title
                        << " (" << gm.year << ") | Rating: " << avg << "/10 (" << n << " total)\n";
                }
                out << "Platform: " << gm.platform << "\n";
                out << "Genre: " << gm.genre << "\n";
                out << "ESRB: " << gm.esrb << "\n";
                out << "Available: " << (gm.available ? "Yes" : "No") << "\n";
                out << "Copies: " << gm.copies << "\n";
                out << "---------------------------------------\n";
                return out.str();
            }
        }
    }
    return "404 Game not found";
}

//CHECKOUT
std::string handleCheckout(const std::string &clientAddr, int gameId, std::vector<Game> &games) {
    // Makes sure user doesn't have it checked out already.
    std::lock_guard<std::mutex> lock(rentalMutex);
    auto &uHist = userRentalHistory[clientAddr];
    for (auto it = uHist.rbegin(); it != uHist.rend(); ++it) {
        if (it->gameId == gameId && it->action=="CHECKOUT") {
            bool returned = false;
            for (auto it2 = uHist.rbegin(); it2 != it; ++it2) {
                if (it2->gameId == gameId && it2->action=="RETURN") {
                    returned = true;
                    break;
                }
            }
            if (!returned) {
                return "403 Checkout failed - You already have this game checked out.";
            }
        }
    }
    // Checks if game is available.
    for (auto &gm : games) {
        if (gm.id == gameId) {
            if (!gm.available || gm.copies <= 0) {
                return "403 Checkout failed - Game is unavailable.";
            }
            gm.copies--;
            if (gm.copies==0) {
                gm.available = false;
            }
            userRentalHistory[clientAddr].push_back({gameId, "CHECKOUT", getCurrentTimestamp()});
            return "250 Checkout success - Enjoy " + gm.title;
        }
    }
    return "404 Checkout failed - Game not found.";
}

//RETURN
std::string handleReturn(const std::string &clientAddr, int gameId, std::vector<Game> &games) {
    // Make sure user has it checked out first.
    std::lock_guard<std::mutex> lock(rentalMutex);
    auto &uHist = userRentalHistory[clientAddr];
    auto it = std::find_if(uHist.rbegin(), uHist.rend(),
                           [gameId](const RentalRecord &r){
                               return (r.gameId == gameId && r.action=="CHECKOUT");
                           });
    if (it == uHist.rend()) {
        return "404 Return failed - You have not rented this game.";
    }
    // Make sure not already returned
    for (auto it2 = uHist.rbegin(); it2 != it; ++it2) {
        if (it2->gameId == gameId && it2->action=="RETURN") {
            return "404 Return failed - You have not rented this game.";
        }
    }
    userRentalHistory[clientAddr].push_back({gameId, "RETURN", getCurrentTimestamp()});
    for (auto &gm : games) {
        if (gm.id == gameId) {
            gm.copies++;
            gm.available = true;
            return "250 Return success - Thank you for returning " + gm.title;
        }
    }
    return "404 Return failed - Game data not found.";
}

//HISTORY
std::string handleHistory(const std::string &clientAddr, const std::vector<Game> &games) {
    std::lock_guard<std::mutex> lock(ratingMutex);
    if (userRentalHistory[clientAddr].empty()) {
        return "304 No rental history found.";
    }
    std::ostringstream out;
    out << "250 Rental history:\n";
    for (auto &record : userRentalHistory[clientAddr]) {
        for (auto &gm : games) {
            if (gm.id == record.gameId) {
                out << "[" << record.timestamp << "] ";
                if (record.action=="CHECKOUT") {
                    out << "Checked out ";
                } else {
                    out << "Returned ";
                }
                out << gm.title << " (" << gm.platform << ")\n";
                break;
            }
        }
    }
    return out.str();
}

//RECOMMEND
std::string handleRecommend(const std::string &clientAddr,
                            const std::vector<Game> &games,
                            const std::string &filterType) {
    auto it = userRentalHistory.find(clientAddr);
    if (it == userRentalHistory.end() || it->second.empty()) {
        return "304 No rental history found. Rent some games first.";
    }

    const auto &records = it->second;
    std::vector<int> rentedGames;
    std::string lastGenre, lastPlatform;

    // Store rented game IDs and grab the first rented game's genre/platform
    for (const auto &r : records) {
        rentedGames.push_back(r.gameId);
        for (const auto &gm : games) {
            if (gm.id == r.gameId) {
                lastGenre = gm.genre;
                lastPlatform = gm.platform;
                break; // Stop after the first found game
            }
        }
    }

    std::ostringstream out;
    out << "250 Game recommendations:\n";
    int count = 0;

    // Recommend games that match the last rented genre/platform
    for (const auto &gm : games) {
        bool alreadyRented = false;

        // Check if the game has already been rented
        for (int rentedId : rentedGames) {
            if (gm.id == rentedId) {
                alreadyRented = true;
                break;
            }
        }

        if (!alreadyRented) {
            bool matches = false;
            if (filterType == "platform" && gm.platform == lastPlatform) {
                matches = true;
            } else if (filterType == "genre" && gm.genre == lastGenre) {
                matches = true;
            } else if (filterType.empty() && (gm.genre == lastGenre || gm.platform == lastPlatform)) {
                matches = true;
            }

            if (matches) {
                out << "ID: " << gm.id << " | " << gm.title << " (" << gm.year << ")\n";
                out << "   Platform: " << gm.platform << "\n";
                out << "   Genre: " << gm.genre << "\n";
                out << "   Available: " << (gm.available ? "Yes" : "No") << "\n";
                out << "   Copies: " << gm.copies << "\n\n";
                count++;
            }
        }

        if (count >= 3) break; // Stop after 3 recommendations
    }

    if (count == 0) {
        return "304 No recommendations available based on your history.";
    }

    return out.str();
}

//RATE
std::string handleRate(const std::string &clientAddr, int gameId, int ratingVal,
                       const std::vector<Game> &games) {
    // Updates the rating if user has actually rented the game.
    std::lock_guard<std::mutex> lock(ratingMutex);
    if (ratingVal < 1 || ratingVal > 10) {
        return "400 BAD REQUEST - Rating must be between 1 and 10.";
    }
    auto &hist = userRentalHistory[clientAddr];
    auto it = std::find_if(hist.begin(), hist.end(),
                           [gameId](const RentalRecord &r){
                               return (r.gameId == gameId && r.action=="CHECKOUT");
                           });
    if (it == hist.end()) {
        return "403 Rate failed - You must rent the game before rating it.";
    }
    auto &rd = globalRatings[gameId];
    if (userRatings[clientAddr].count(gameId) > 0) {
        int old = userRatings[clientAddr][gameId];
        rd.totalRating -= old;
    } else {
        rd.numRatings++;
    }
    rd.totalRating += ratingVal;
    userRatings[clientAddr][gameId] = ratingVal;
    std::string gameTitle = "Unknown";
    for (auto &gm : games) {
        if (gm.id == gameId) {
            gameTitle = gm.title;
            break;
        }
    }
    std::ostringstream out;
    out << "250 Rate success - You rated \"" << gameTitle << "\" " << ratingVal << "/10.";
    return out.str();
}

// Forward declarations for authentication functions
std::string handleUser(const std::string &username, bool &authenticated, std::string &currentUser);
std::string handlePass(const std::string &password, bool &authenticated, std::string &currentUser,
                      bool &browseMode, bool &rentMode, bool &myGamesMode);

// handleCommand
std::string handleCommand(const std::string &command,
                          const std::string &clientAddr,
                          bool &authenticated,
                          bool &browseMode,
                          bool &rentMode,
                          bool &myGamesMode,
                          std::vector<Game> &games,
                          std::string &currentUser) {

    // Debug print for every command
    std::cout << "Received command: '" << command << "'" << std::endl;
    std::cout << "Auth state: " << (authenticated ? "Authenticated" : "Not Authenticated") << std::endl;
    std::cout << "Current User: '" << currentUser << "'" << std::endl;
    std::cout << "Modes: " << (browseMode ? "Browse " : "") 
              << (rentMode ? "Rent " : "") 
              << (myGamesMode ? "MyGames" : "") << std::endl;

    // Check for empty command
    if (command.empty()) {
        std::cout << "Warning: Empty command received" << std::endl;
        return "400 BAD REQUEST - Empty command";
    }

    // USER/PASS commands don't require authentication
    if (command.rfind("USER ", 0) == 0) {
        return handleUser(command.substr(5), authenticated, currentUser);
    } 
    else if (command.rfind("PASS ", 0) == 0) {
        return handlePass(command.substr(5), authenticated, currentUser, browseMode, rentMode, myGamesMode);
    }
    
    // All other commands require authentication
    if (!authenticated) {
        return "530 Not authenticated. Please login first with USER and PASS.";
    }
    
    //HELP
    if (command == "HELP") {
        return handleHelp(browseMode, rentMode, myGamesMode);
    }
    //BROWSE
    if (command == "BROWSE") {
        browseMode = true;
        rentMode = false;
        myGamesMode = false;
        return "210 Switched to Browse Mode";
    }
    //RENT
    if (command == "RENT") {
        browseMode = false;
        rentMode = true;
        myGamesMode = false;
        return "220 Switched to Rent Mode";
    }
    //MYGAMES
    if (command == "MYGAMES") {
        browseMode = false;
        rentMode = false;
        myGamesMode = true;
        return "230 Switched to MyGames Mode";
    }
    // BROWSE commands
    if (browseMode) {
        if (command.rfind("LIST", 0) == 0) {
            //LIST
            std::istringstream ss(command);
            std::string c, filter;
            ss >> c >> filter;
            return handleList(games, filter);
        }
        else if (command.rfind("SEARCH", 0) == 0) {
            //SEARCH
            std::istringstream ss(command);
            std::string c, fType, fVal;
            ss >> c >> fType;
            std::getline(ss >> std::ws, fVal);
            if (fType.empty() || fVal.empty()) {
                return "400 BAD REQUEST - SEARCH requires filter and keyword.";
            }
            return handleSearch(games, fType, fVal);
        }
        else if (command.rfind("SHOW", 0) == 0) {
            //SHOW
            return handleShow(games, command);
        }
    }
    // RENT commands
    if (rentMode) {
        if (command.rfind("CHECKOUT ", 0) == 0) {
            //CHECKOUT
            std::istringstream ss(command);
            std::string c;
            int gID;
            ss >> c >> gID;
            return handleCheckout(currentUser, gID, games);  // Use currentUser instead of clientAddr
        }
        else if (command.rfind("RETURN ", 0) == 0) {
            //RETURN
            std::istringstream ss(command);
            std::string c;
            int gID;
            ss >> c >> gID;
            return handleReturn(currentUser, gID, games);  // Use currentUser instead of clientAddr
        }
    }
    // MYGAMES commands
    if (myGamesMode) {
        if (command == "HISTORY") {
            //HISTORY
            return handleHistory(currentUser, games);  // Use currentUser instead of clientAddr
        }
        else if (command.rfind("RECOMMEND", 0) == 0) {
            //RECOMMEND
            std::istringstream ss(command);
            std::string c, f;
            ss >> c >> f;
            if (!f.empty() && f != "platform" && f != "genre") {
                return "400 BAD REQUEST - Invalid filter. Use 'platform' or 'genre'.";
            }
            return handleRecommend(currentUser, games, f);  // Use currentUser instead of clientAddr
        }
        else if (command.rfind("RATE ", 0) == 0) {
            //RATE
            std::istringstream ss(command);
            std::string c;
            int gID, val;
            ss >> c >> gID >> val;
            return handleRate(currentUser, gID, val, games);  // Use currentUser instead of clientAddr
        }
    }
    //BYE
    if (command == "BYE") {
        return "200 BYE";
    }
    // fallback
    return "400 BAD REQUEST";
}

// Forward declaration
int RAND_bytes_range(int max);

// Generate a random 8-character password 
// Must include uppercase, lowercase, digit, and special char
std::string generate_password() {
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string digits = "0123456789";
    const std::string special = "!@#$%^&*";
    
    std::string password;
    
    // Add at least one from each category
    password += uppercase[RAND_bytes_range(uppercase.size())];
    password += lowercase[RAND_bytes_range(lowercase.size())];
    password += digits[RAND_bytes_range(digits.size())];
    password += special[RAND_bytes_range(special.size())];
    
    // Add 4 more random characters
    const std::string all = uppercase + lowercase + digits + special;
    for (int i = 0; i < 4; i++) {
        password += all[RAND_bytes_range(all.size())];
    }
    
    // Shuffle the password
    std::vector<char> password_chars(password.begin(), password.end());
    for (int i = password_chars.size() - 1; i > 0; i--) {
        int j = RAND_bytes_range(i + 1);
        std::swap(password_chars[i], password_chars[j]);
    }
    
    return std::string(password_chars.begin(), password_chars.end());
}

// Helper function to get a random number using RAND_bytes
int RAND_bytes_range(int max) {
    unsigned char rand_byte;
    if (RAND_bytes(&rand_byte, 1) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return rand_byte % max;
}

// Generate a 16-byte random salt
std::vector<unsigned char> generate_salt() {
    std::vector<unsigned char> salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    return salt;
}

// Hash password using PBKDF2-HMAC-SHA256
std::vector<unsigned char> hash_password(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> hash(32); // SHA-256 output is 32 bytes
    
    if (PKCS5_PBKDF2_HMAC(
            password.c_str(), 
            password.length(),
            salt.data(), 
            salt.size(),
            10000,  // 10,000 iterations as required
            EVP_sha256(),
            hash.size(), 
            hash.data()) != 1) {
        throw std::runtime_error("Failed to hash password");
    }
    
    return hash;
}

// Load credentials from file
bool load_credentials() {
    std::lock_guard<std::mutex> lock(credentialMutex);
    
    // Clear existing credentials before loading
    userCredentials.clear();
    
    // Get full path for .games_shadow
    std::string filePath = "./.games_shadow";  // Use relative path for simplicity
    std::cout << "Looking for credential file at: " << filePath << std::endl;
    
    // Check if file exists
    if (!std::filesystem::exists(filePath)) {
        std::cout << "Credential file not found, creating new empty file" << std::endl;
        
        // Create an empty shadow file
        std::ofstream newFile(filePath);
        if (!newFile.is_open()) {
            std::cerr << "ERROR: Cannot create credential file: " << strerror(errno) << std::endl;
            return false;
        }
        newFile.close();
        std::cout << "Created empty credential file" << std::endl;
        return true;
    }
    
    // File exists, try to open it
    std::cout << "Found credential file, loading..." << std::endl;
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "ERROR: Cannot open credential file for reading: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Successfully opened, read line by line
    std::string line;
    int lineCount = 0;
    int successCount = 0;
    
    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) {
            std::cout << "Skipping empty line" << std::endl;
            continue;
        }
        
        lineCount++;
        std::cout << "Processing line " << lineCount << ": " << line << std::endl;
        
        // Split into username and credential data
        std::istringstream iss(line);
        std::string username, record;
        
        if (std::getline(iss, username, ':') && std::getline(iss, record)) {
            // Parse: $pbkdf2-sha256$work_factor$salt_base64$hash_base64
            if (record.substr(0, 14) != "$pbkdf2-sha256$") {
                std::cerr << "Invalid credential format for user: " << username << std::endl;
                continue;
            }
            
            size_t pos1 = record.find('$', 14);
            size_t pos2 = record.find('$', pos1 + 1);
            
            if (pos1 == std::string::npos || pos2 == std::string::npos) {
                std::cerr << "Invalid credential format for user: " << username << std::endl;
                continue;
            }
            
            std::string work_factor = record.substr(14, pos1 - 14);
            std::string salt_base64 = record.substr(pos1 + 1, pos2 - pos1 - 1);
            std::string hash_base64 = record.substr(pos2 + 1);
            
            std::cout << "  Username: " << username << std::endl;
            std::cout << "  Work Factor: " << work_factor << std::endl;
            std::cout << "  Salt (Base64): " << salt_base64 << std::endl;
            std::cout << "  Hash (Base64): " << hash_base64 << std::endl;
            
            UserCredential cred;
            cred.username = username;
            cred.salt = salt_base64;
            cred.hash = hash_base64;
            cred.failedAttempts = 0;
            
            userCredentials[username] = cred;
            std::cout << "Successfully loaded user: " << username << std::endl;
            successCount++;
        } else {
            std::cerr << "Malformed line in credentials file, line " << lineCount << std::endl;
        }
    }
    
    file.close();
    std::cout << "Credential loading complete. Loaded " << successCount << " out of " << lineCount << " entries." << std::endl;
    
    // Debug: print all loaded users
    std::cout << "Currently loaded users: ";
    for (const auto& [username, _] : userCredentials) {
        std::cout << username << " ";
    }
    std::cout << std::endl;
    
    return true;
}

// Save credentials to file
bool save_credentials() {
    // Use a simpler, more direct approach with C++ streams
    
    std::string filePath = "./.games_shadow";  // Use relative path for simplicity
    std::cout << "Saving credentials to: " << filePath << std::endl;
    
    // Debug: show users being saved
    std::cout << "Saving users: ";
    for (const auto& [username, _] : userCredentials) {
        std::cout << username << " ";
    }
    std::cout << std::endl;
    
    // First create a temporary file
    std::string tempFilePath = filePath + ".tmp";
    
    // Open output file
    std::ofstream outFile(tempFilePath);
    if (!outFile.is_open()) {
        std::cerr << "ERROR: Failed to open temporary file for writing: " << strerror(errno) << std::endl;
        return false;
    }
    
    int count = 0;
    
    // Write each credential
    for (const auto& [username, cred] : userCredentials) {
        std::string line = username + ":$pbkdf2-sha256$10000$" + cred.salt + "$" + cred.hash + "\n";
        std::cout << "Writing user: " << username << std::endl;
        
        outFile << line;
        if (!outFile.good()) {
            std::cerr << "ERROR: Failed to write user " << username << " to file: " << strerror(errno) << std::endl;
            outFile.close();
            return false;
        }
        count++;
    }
    
    // Flush and close the file
    outFile.flush();
    outFile.close();
    
    if (!outFile) {
        std::cerr << "ERROR: Problem closing temporary file: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Rename temporary file to the actual file (atomic operation)
    std::error_code ec;
    std::filesystem::rename(tempFilePath, filePath, ec);
    if (ec) {
        std::cerr << "ERROR: Failed to rename temporary file: " << ec.message() << std::endl;
        return false;
    }
    
    std::cout << "Successfully saved " << count << " credential records" << std::endl;
    return true;
}

// Handle USER command - this checks if the user exists or starts registration
std::string handleUser(const std::string &username, bool &authenticated, std::string &currentUser) {
    std::lock_guard<std::mutex> lock(credentialMutex);
    
    currentUser = username;
    authenticated = false;
    
    // Check if user exists
    auto it = userCredentials.find(username);
    if (it != userCredentials.end()) {
        // Reset failed attempts if this is a new login attempt
        it->second.failedAttempts = 0;
        return "331 User name okay, need password.";
    } else {
        // User doesn't exist, prepare for registration
        return "331 New user, need password to create account.";
    }
}

// Handle PASS command - authenticate user or register new user
std::string handlePass(const std::string &password, bool &authenticated, std::string &currentUser,
                      bool &browseMode, bool &rentMode, bool &myGamesMode) {
    std::lock_guard<std::mutex> lock(credentialMutex);
    
    std::cout << "Processing PASS command for user: " << currentUser << std::endl;
    
    // Check if user exists
    auto it = userCredentials.find(currentUser);
    if (it != userCredentials.end()) {
        // User exists, authenticate
        std::cout << "Existing user found, performing authentication" << std::endl;
        UserCredential &cred = it->second;
        
        // Check for too many failed attempts
        if (cred.failedAttempts >= 2) {
            std::cout << "Too many failed attempts for user: " << currentUser << std::endl;
            return "530 Authentication failed: too many invalid attempts.";
        }
        
        try {
            // Decode the stored salt
            std::cout << "Decoding salt: " << cred.salt << std::endl;
            auto salt_bin = base64_decode(cred.salt);
            std::cout << "Salt decoded, size: " << salt_bin.size() << " bytes" << std::endl;
            
            // Hash the provided password with the stored salt
            std::cout << "Hashing password: '" << password << "'" << std::endl;
            auto hash = hash_password(password, salt_bin);
            std::string hash_b64 = base64_encode(hash.data(), hash.size());
            
            std::cout << "Comparing hashes:" << std::endl;
            std::cout << "  Stored hash: " << cred.hash << std::endl;
            std::cout << "  Computed hash: " << hash_b64 << std::endl;
            
            // Compare with stored hash
            if (hash_b64 == cred.hash) {
                authenticated = true;
                cred.failedAttempts = 0;
                // Default to browse mode for existing users too
                browseMode = true;
                rentMode = false;
                myGamesMode = false;
                std::cout << "Authentication successful for user: " << currentUser << std::endl;
                // CRITICAL FIX: Absolutely minimal response for OpenSSL s_client
                return "230 OK";
            } else {
                // Failed authentication
                cred.failedAttempts++;
                authenticated = false;
                
                std::cout << "Authentication failed for user: " << currentUser << std::endl;
                std::cout << "Failed attempts: " << cred.failedAttempts << "/2" << std::endl;
                return "530 Authentication failed: Invalid password";
            }
        } catch (const std::exception& e) {
            std::cerr << "Exception during authentication: " << e.what() << std::endl;
            return "500 INTERNAL SERVER ERROR - Exception during authentication";
        }
    } else {
        // Register new user - we'll do this in a separate function to avoid deadlocks
        std::cout << "Registering new user: " << currentUser << std::endl;
        
        try {
            // Generate random password if none provided
            std::string userPassword = password;
            if (userPassword.empty()) {
                userPassword = generate_password();
                std::cout << "Generated random password: " << userPassword << std::endl;
            } else {
                std::cout << "Using provided password" << std::endl;
            }
            
            // Generate salt and hash outside the lock to minimize lock time
            auto salt = generate_salt();
            std::cout << "Generated salt, size: " << salt.size() << " bytes" << std::endl;
            
            auto hash = hash_password(userPassword, salt);
            std::cout << "Generated hash, size: " << hash.size() << " bytes" << std::endl;
            
            // Convert binary salt and hash to base64 for storage
            std::string salt_b64 = base64_encode(salt.data(), salt.size());
            std::string hash_b64 = base64_encode(hash.data(), hash.size());
            
            std::cout << "Encoded salt: " << salt_b64 << std::endl;
            std::cout << "Encoded hash: " << hash_b64 << std::endl;
            
            // Create credential object
            UserCredential cred;
            cred.username = currentUser;
            cred.salt = salt_b64;
            cred.hash = hash_b64;
            cred.failedAttempts = 0;
            
            // Store in memory and release the lock temporarily
            userCredentials[currentUser] = cred;
            
            // Log that we're saving credentials
            std::cout << "Saving credentials to file" << std::endl;
            
            // Save credentials but continue even if it fails
            bool saveResult = save_credentials();
            if (!saveResult) {
                std::cerr << "Failed to save credentials to file, but continuing" << std::endl;
            } else {
                std::cout << "Credentials saved successfully" << std::endl;
            }
            
            // Set the user as authenticated and enable browse mode by default
            authenticated = true;
            browseMode = true;
            rentMode = false;
            myGamesMode = false;
            
            // Simple, minimal single-line response that's easier for s_client to display
            std::cout << "Authentication successful for new user: " << currentUser << std::endl;
            
            // If we generated a password, tell the user what it is
            if (password.empty()) {
                return "230 New user created. Your password is: " + userPassword;
            } else {
                return "230 New user account created successfully";
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Exception during credential preparation: " << e.what() << std::endl;
            return "500 INTERNAL SERVER ERROR - Exception during registration";
        }
    }
    
    // This should never be reached, but just in case
    std::cout << "WARNING: Reached end of handlePass function without early return" << std::endl;
    if (authenticated) {
        return "230 User login successful";
    } else {
        return "530 Authentication failed";
    }
}

// Generate a random password for a new user
std::string handleNewUser(const std::string &username) {
    std::lock_guard<std::mutex> lock(credentialMutex);
    
    // Generate random password
    std::string password = generate_password();
    
    // Generate salt and hash
    auto salt = generate_salt();
    auto hash = hash_password(password, salt);
    
    // Convert binary salt and hash to base64 for storage
    std::string salt_b64 = base64_encode(salt.data(), salt.size());
    std::string hash_b64 = base64_encode(hash.data(), hash.size());
    
    // Store new credentials
    UserCredential cred;
    cred.username = username;
    cred.salt = salt_b64;
    cred.hash = hash_b64;
    cred.failedAttempts = 0;
    
    userCredentials[username] = cred;
    
    // Save to file
    if (!save_credentials()) {
        return "500 INTERNAL SERVER ERROR - Failed to save credentials";
    }
    
    return "230 New user created. Your password is: " + password;
}

int main(int argc, char* argv[]) {
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    if (argc != 2) {
        std::cerr << std::format("Usage: {} <config_file>\n", *argv);
        return 1;
    }

    std::string configFileName = argv[1];
    std::string port = getPortFromConfig(configFileName);
    if (port.empty()) {
        std::cerr << "Port number not found in configuration file!\n";
        return 1;
    }

    // Initialize OpenSSL
    if (!init_openssl()) {
        std::cerr << "Failed to initialize OpenSSL" << std::endl;
        return 1;
    }

    // Load user credentials from .games_shadow file
    if (!load_credentials()) {
        std::cerr << "Failed to load user credentials" << std::endl;
        cleanup_openssl();
        return 1;
    }

    std::vector<Game> games = loadGamesFromFile("games.db");

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(nullptr, port.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << std::format("getaddrinfo: {}\n", gai_strerror(rv));
        cleanup_openssl();
        return 1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            throw std::system_error(errno, std::generic_category(), "setsockopt");
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if (p == NULL) {
        std::cerr << "server: failed to bind\n";
        cleanup_openssl();
        return 2;
    }
    if (listen(sockfd, BACKLOG) == -1) {
        cleanup_openssl();
        throw std::system_error(errno, std::generic_category(), "listen");
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        cleanup_openssl();
        throw std::system_error(errno, std::generic_category(), "sigaction");
    }

    std::cout << "server: waiting for connections...\n";

    while (true) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
        logEvent("Connection from: " + std::string(s));

        std::thread clientThread([new_fd, s, &games]() {
            std::string clientAddress(s);
            logEvent("Starting TLS handshake with client: " + clientAddress);
            
            try {
                // Create SSL connection and perform handshake
                SSLConnection ssl_conn(new_fd);
                if (!ssl_conn.accept()) {
                    logEvent("TLS handshake failed with client: " + clientAddress);
                    return;
                }
                
                logEvent("TLS handshake successful with client: " + clientAddress);
                
                std::array<char, MAXDATASIZE> buf;
                int numbytes;

                bool authenticated = false;
                bool browseMode = false;
                bool rentMode = false;
                bool myGamesMode = false;
                std::string currentUser;

                while (true) {
                    numbytes = ssl_conn.read(buf.data(), MAXDATASIZE - 1);
                    if (numbytes <= 0) {
                        int ssl_error = SSL_get_error(ssl_conn.ssl, numbytes);
                        if (numbytes < 0) {
                            std::cerr << "SSL read error: " << ssl_error << std::endl;
                            ERR_print_errors_fp(stderr);
                            
                            // Check for specific errors
                            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                                std::cerr << "SSL operation would block, retrying..." << std::endl;
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                                continue;  // Try again
                            }
                        }
                        logEvent("Client disconnected: " + clientAddress);
                        break;
                    }
                    
                    buf[numbytes] = '\0';
                    
                    // Clean up received command by removing any trailing whitespace/newlines
                    std::string received(buf.data());
                    
                    // Trim trailing whitespace, CR, LF
                    size_t endPos = received.find_last_not_of(" \r\n\t");
                    if (endPos != std::string::npos) {
                        received = received.substr(0, endPos + 1);
                    } else if (received.find_first_not_of(" \r\n\t") == std::string::npos) {
                        // String is all whitespace
                        received = "";
                    }
                    
                    std::cout << "Raw input: '" << buf.data() << "'" << std::endl;
                    std::cout << "Cleaned command: '" << received << "'" << std::endl;

                    std::string response = handleCommand(
                        received, clientAddress,
                        authenticated, browseMode,
                        rentMode, myGamesMode,
                        games, currentUser
                    );
                    
                    // Debug output
                    std::cout << "Response to send (length: " << response.length() << " bytes): " << std::endl;
                    std::cout << "---BEGIN RESPONSE---" << std::endl;
                    std::cout << response << std::endl;
                    std::cout << "---END RESPONSE---" << std::endl;
                    
                    // Simple response format with just a CRLF trailer
                    std::string minimal_response = response + "\r\n";
                    
                    // Log what we're sending
                    std::cout << "Sending response (length: " << minimal_response.length() << "): \"" 
                              << response << "\\r\\n\"" << std::endl;
                    
                    // Direct SSL_write with minimal formatting
                    int direct_result = SSL_write(ssl_conn.ssl, minimal_response.c_str(), minimal_response.length());
                    
                    if (direct_result <= 0) {
                        int ssl_error = SSL_get_error(ssl_conn.ssl, direct_result);
                        std::cerr << "SSL write error: " << ssl_error << std::endl;
                        ERR_print_errors_fp(stderr);
                        
                        // Check if it's a temporary error we should retry
                        if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_READ) {
                            std::cerr << "SSL operation would block, retrying write..." << std::endl;
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            // Retry a few times
                            for (int retry = 0; retry < 3; retry++) {
                                direct_result = SSL_write(ssl_conn.ssl, minimal_response.c_str(), minimal_response.length());
                                if (direct_result > 0) break;
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            }
                            
                            if (direct_result <= 0) {
                                std::cerr << "SSL write failed after retries" << std::endl;
                                break;
                            }
                        } else {
                            // Serious error, terminate connection
                            break;
                        }
                    }
                    
                    std::cout << "Successfully sent " << direct_result << " bytes" << std::endl;
                    
                    if (response.rfind("200 BYE", 0) == 0) {
                        logEvent("Client disconnected: " + clientAddress);
                        break;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Exception in client thread: " << e.what() << std::endl;
            }
            
            // The SSLConnection destructor will clean up the connection and close the socket
        });
        clientThread.detach();
    }

    // Clean up OpenSSL
    cleanup_openssl();

    return 0;
}
