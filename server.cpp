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
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <functional>
#include <cctype>
#include <random>
#include <stdexcept>

// Network headers
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// System headers
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <csignal>
#include <fcntl.h>

// Server configuration
#define BACKLOG 10
#define MAXDATASIZE 4096

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
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        std::cerr << "Failed to set TLS version" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    // Configure the cipher suites for TLS 1.3
    if (SSL_CTX_set_ciphersuites(ssl_ctx, 
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1) {
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
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    
    BIO_write(b64, data, length);
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    
    return result;
}

// Base64 decoding function
std::vector<unsigned char> base64_decode(const std::string& encoded_data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    BIO* bmem = BIO_new_mem_buf(encoded_data.c_str(), encoded_data.length());
    bmem = BIO_push(b64, bmem);
    
    std::vector<unsigned char> result(encoded_data.length());
    int decoded_size = BIO_read(bmem, result.data(), encoded_data.length());
    
    if (decoded_size <= 0) {
        std::cerr << "Failed to decode base64 data" << std::endl;
        ERR_print_errors_fp(stderr);
    }
    
    result.resize(decoded_size > 0 ? decoded_size : 0);
    BIO_free_all(bmem);
    
    return result;
}

// Wrapper for SSL connection
class SSLConnection {
public:
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
    
    // Send a response to the client
    bool send_response(const std::string& response) {
        std::string full_response = response + "\r\n";
        int result = SSL_write(ssl, full_response.c_str(), full_response.length());
        return result > 0;
    }
};

// Data structures
struct RentalRecord {
    int gameId;
    std::string action; // "CHECKOUT" or "RETURN"
    std::string timestamp;
};

struct RatingData {
    int totalRating = 0;
    int numRatings = 0;
};

struct UserCredential {
    std::string username;
    std::string salt;       // Base64 encoded
    std::string hash;       // Base64 encoded
    int failedAttempts;     // Count of consecutive failed login attempts
};

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

// Global data stores with mutex protection
static std::unordered_map<std::string, std::vector<RentalRecord>> userRentalHistory;
static std::mutex rentalMutex;

static std::unordered_map<int, RatingData> globalRatings;
static std::unordered_map<std::string, std::unordered_map<int,int>> userRatings;
static std::mutex ratingMutex;

static std::unordered_map<std::string, UserCredential> userCredentials;
static std::mutex credentialMutex;

// Utility functions
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void logEvent(const std::string& msg) {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S") << "] " << msg << std::endl;
}

// Signal handlers
void sigchld_handler(int s) {
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    errno = saved_errno;
}

void terminate_handler(int s) {
    std::cout << "Server is shutting down..." << std::endl;
    
    // Delete the .games_shadow file
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::string filePath = std::string(cwd) + "/.games_shadow";
        if (std::filesystem::exists(filePath)) {
            std::cout << "Deleting credentials file: " << filePath << std::endl;
            std::filesystem::remove(filePath);
        }
    }
    
    cleanup_openssl();
    exit(0);
}

// Network helper functions
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

std::string getPortFromConfig(const std::string& fileName) {
    std::ifstream cf(fileName);
    if (!cf.is_open()) {
        std::cerr << "Error opening configuration file: " << fileName << std::endl;
        return "";
    }
    
    std::string line;
    while (std::getline(cf, line)) {
        if (line.substr(0, 5) == "PORT=") {
            return line.substr(5);
        }
    }
    return "";
}

// Load games from database file
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
        if (lineNumber == 1) continue; // skip header
        
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

// Password and authentication functions
int random_range(int max) {
    unsigned char rand_byte;
    if (RAND_bytes(&rand_byte, 1) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return rand_byte % max;
}

std::string generate_password() {
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string digits = "0123456789";
    const std::string special = "!@#$%^&*_-+=";
    
    std::string password;
    
    // Add at least one from each category
    password += uppercase[random_range(uppercase.size())];
    password += lowercase[random_range(lowercase.size())];
    password += digits[random_range(digits.size())];
    password += special[random_range(special.size())];
    
    // Add 4 more random characters
    const std::string all = uppercase + lowercase + digits + special;
    for (int i = 0; i < 4; i++) {
        password += all[random_range(all.size())];
    }
    
    // Shuffle the password
    for (int i = password.size() - 1; i > 0; i--) {
        int j = random_range(i + 1);
        std::swap(password[i], password[j]);
    }
    
    return password;
}

std::vector<unsigned char> generate_salt() {
    std::vector<unsigned char> salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    return salt;
}

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
    
    // Clear existing credentials
    userCredentials.clear();
    
    // Get path for .games_shadow
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Failed to get current working directory" << std::endl;
        return false;
    }
    
    std::string filePath = std::string(cwd) + "/.games_shadow";
    
    // Check if file exists
    if (!std::filesystem::exists(filePath)) {
        std::cout << "Credential file not found, creating new empty file" << std::endl;
        
        // Create an empty shadow file
        std::ofstream newFile(filePath);
        if (!newFile.is_open()) {
            std::cerr << "Cannot create credential file" << std::endl;
            return false;
        }
        newFile.close();
        return true;  // No users to load yet
    }
    
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Cannot open credential file for reading" << std::endl;
        return false;
    }
    
    std::string line;
    int loadedCount = 0;
    
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        
        // Split username and credential on colon
        size_t colonPos = line.find(':');
        if (colonPos == std::string::npos) {
            std::cerr << "Invalid line format: Missing colon separator" << std::endl;
            continue;
        }
        
        std::string username = line.substr(0, colonPos);
        std::string record = line.substr(colonPos + 1);
        
        // Trim whitespace
        username.erase(0, username.find_first_not_of(" \t\r\n"));
        username.erase(username.find_last_not_of(" \t\r\n") + 1);
        record.erase(0, record.find_first_not_of(" \t\r\n"));
        record.erase(record.find_last_not_of(" \t\r\n") + 1);
        
        // Convert username to lowercase
        std::transform(username.begin(), username.end(), username.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        // Ensure record is valid PBKDF2 format
        if (record.find("$pbkdf2-sha256$") != 0) {
            std::cerr << "Invalid credential format for user: " << username << std::endl;
            continue;
        }
        
        // Parse the components
        size_t firstDollar = record.find('$');
        size_t secondDollar = record.find('$', firstDollar + 1);
        size_t thirdDollar = record.find('$', secondDollar + 1);
        size_t fourthDollar = record.find('$', thirdDollar + 1);
        
        if (firstDollar == std::string::npos || secondDollar == std::string::npos || 
            thirdDollar == std::string::npos || fourthDollar == std::string::npos) {
            std::cerr << "Malformed record for user: " << username << std::endl;
            continue;
        }
        
        std::string workFactorStr = record.substr(secondDollar + 1, thirdDollar - secondDollar - 1);
        std::string saltBase64 = record.substr(thirdDollar + 1, fourthDollar - thirdDollar - 1);
        std::string hashBase64 = record.substr(fourthDollar + 1);
        
        // Store the credential
        UserCredential cred;
        cred.username = username;
        cred.salt = saltBase64;
        cred.hash = hashBase64;
        cred.failedAttempts = 0;
        
        userCredentials[username] = cred;
        loadedCount++;
    }
    
    file.close();
    std::cout << "Loaded " << loadedCount << " user credentials" << std::endl;
    return true;
}

// Save credentials to file
bool save_credentials() {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Failed to get current working directory" << std::endl;
        return false;
    }
    
    std::string filePath = std::string(cwd) + "/.games_shadow";
    std::string tempFilePath = filePath + ".tmp";
    
    // Open output file
    std::ofstream outFile(tempFilePath);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open temporary file for writing" << std::endl;
        return false;
    }
    
    // Write each credential
    for (const auto& [username, cred] : userCredentials) {
        std::string line = username + ":$pbkdf2-sha256$10000$" + cred.salt + "$" + cred.hash + "\n";
        outFile << line;
    }
    
    outFile.close();
    
    // Rename temporary file to the actual file
    try {
        std::filesystem::rename(tempFilePath, filePath);
    } catch (const std::exception& e) {
        std::cerr << "Failed to rename temporary file: " << e.what() << std::endl;
        return false;
    }
    
    return true;
}

// Command handlers
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
        out << "  RATING <game_id>\n";
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
        out << "RATING <game_id>\n";
        out << "BROWSE\n";
        out << "RENT\n";
        out << "HELP\n";
        out << "BYE\n";
    }
    out << "-------------------------------------------\n";
    return out.str();
}

std::string handleList(const std::vector<Game> &games, const std::string &filterType) {
    // If no filter, list everything or 304 if empty
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
            if (availFlag == "availability") {
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
                if (globalRatings.count(gm.id) && globalRatings[gm.id].numRatings > 0) {
                    avg = (double)globalRatings[gm.id].totalRating / globalRatings[gm.id].numRatings;
                    n = globalRatings[gm.id].numRatings;
                }
                
                std::ostringstream out;
                out << "250 Game details\n";
                out << "---------------------------------------\n";
                if (n == 0) {
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

std::string handleCheckout(const std::string &username, int gameId, std::vector<Game> &games) {
    std::lock_guard<std::mutex> lock(rentalMutex);
    
    // Check if user exists in map, create entry if not
    auto historyIt = userRentalHistory.find(username);
    if (historyIt == userRentalHistory.end()) {
        // First checkout for this user
        userRentalHistory[username] = {};
    } else {
        // Check if user already has this game
        auto &uHist = historyIt->second;
        for (auto it = uHist.rbegin(); it != uHist.rend(); ++it) {
            if (it->gameId == gameId && it->action == "CHECKOUT") {
                bool returned = false;
                for (auto it2 = uHist.rbegin(); it2 != it; ++it2) {
                    if (it2->gameId == gameId && it2->action == "RETURN") {
                        returned = true;
                        break;
                    }
                }
                if (!returned) {
                    return "403 Checkout failed - You already have this game checked out.";
                }
            }
        }
    }
    
    // Check if game is available
    for (auto &gm : games) {
        if (gm.id == gameId) {
            if (!gm.available || gm.copies <= 0) {
                return "403 Checkout failed - Game is unavailable.";
            }
            
            // Update game availability
            gm.copies--;
            if (gm.copies == 0) {
                gm.available = false;
            }
            
            // Record rental
            userRentalHistory[username].push_back({gameId, "CHECKOUT", getCurrentTimestamp()});
            
            return "250 Checkout success - Enjoy " + gm.title;
        }
    }
    
    return "404 Checkout failed - Game not found.";
}

std::string handleReturn(const std::string &username, int gameId, std::vector<Game> &games) {
    std::lock_guard<std::mutex> lock(rentalMutex);
    
    // Check if user exists and has rented this game
    auto historyIt = userRentalHistory.find(username);
    if (historyIt == userRentalHistory.end()) {
        return "404 Return failed - You have not rented this game.";
    }
    
    auto &uHist = historyIt->second;
    auto it = std::find_if(uHist.rbegin(), uHist.rend(),
                         [gameId](const RentalRecord &r){
                             return (r.gameId == gameId && r.action == "CHECKOUT");
                         });
    
    if (it == uHist.rend()) {
        return "404 Return failed - You have not rented this game.";
    }
    
    // Check if already returned
    for (auto it2 = uHist.rbegin(); it2 != it; ++it2) {
        if (it2->gameId == gameId && it2->action == "RETURN") {
            return "404 Return failed - You have not rented this game.";
        }
    }
    
    // Record return
    userRentalHistory[username].push_back({gameId, "RETURN", getCurrentTimestamp()});
    
    // Update game availability
    for (auto &gm : games) {
        if (gm.id == gameId) {
            gm.copies++;
            gm.available = true;
            return "250 Return success - Thank you for returning " + gm.title;
        }
    }
    
    return "404 Return failed - Game data not found.";
}

std::string handleHistory(const std::string &username, const std::vector<Game> &games) {
    std::lock_guard<std::mutex> lock(rentalMutex);
    
    // Check if this user has rental history
    auto historyIt = userRentalHistory.find(username);
    if (historyIt == userRentalHistory.end() || historyIt->second.empty()) {
        return "304 No rental history found.";
    }
    
    std::ostringstream out;
    out << "250 Rental history:\n";
    
    // Show this user's rental history
    const auto &userHistory = historyIt->second;
    for (const auto &record : userHistory) {
        for (const auto &gm : games) {
            if (gm.id == record.gameId) {
                out << "[" << record.timestamp << "] ";
                out << (record.action == "CHECKOUT" ? "Checked out " : "Returned ");
                out << gm.title << " (" << gm.platform << ")\n";
                break;
            }
        }
    }
    
    return out.str();
}

std::string handleRecommend(const std::string &username,
                          const std::vector<Game> &games,
                          const std::string &filterType) {
    std::lock_guard<std::mutex> lock(rentalMutex);
    
    // Check for rental history
    auto it = userRentalHistory.find(username);
    if (it == userRentalHistory.end() || it->second.empty()) {
        return "304 No rental history found. Rent some games first.";
    }

    // Find previously rented games and their genres/platforms
    const auto &records = it->second;
    std::vector<int> rentedGames;
    std::string lastGenre, lastPlatform;

    for (const auto &r : records) {
        rentedGames.push_back(r.gameId);
        for (const auto &gm : games) {
            if (gm.id == r.gameId) {
                lastGenre = gm.genre;
                lastPlatform = gm.platform;
                break;
            }
        }
    }

    // Generate recommendations
    std::ostringstream out;
    out << "250 Game recommendations:\n";
    int count = 0;

    for (const auto &gm : games) {
        // Skip already rented games
        if (std::find(rentedGames.begin(), rentedGames.end(), gm.id) != rentedGames.end()) {
            continue;
        }

        // Check for matches based on filter
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

        if (count >= 3) break; // Stop after 3 recommendations
    }

    if (count == 0) {
        return "304 No recommendations available based on your history.";
    }

    return out.str();
}

std::string handleRate(const std::string &username, int gameId, int ratingVal,
                     const std::vector<Game> &games) {
    std::lock_guard<std::mutex> lock(ratingMutex);
    
    // Validate rating
    if (ratingVal < 1 || ratingVal > 10) {
        return "400 BAD REQUEST - Rating must be between 1 and 10.";
    }
    
    // Verify user has rented this game
    auto historyIt = userRentalHistory.find(username);
    if (historyIt == userRentalHistory.end()) {
        return "403 Rate failed - You must rent the game before rating it.";
    }
    
    auto &hist = historyIt->second;
    auto it = std::find_if(hist.begin(), hist.end(),
                         [gameId](const RentalRecord &r){
                             return (r.gameId == gameId && r.action == "CHECKOUT");
                         });
    
    if (it == hist.end()) {
        return "403 Rate failed - You must rent the game before rating it.";
    }
    
    // Update ratings
    auto &rd = globalRatings[gameId];
    if (userRatings[username].count(gameId) > 0) {
        // Update existing rating
        int old = userRatings[username][gameId];
        rd.totalRating -= old;
    } else {
        // First time rating
        rd.numRatings++;
    }
    
    rd.totalRating += ratingVal;
    userRatings[username][gameId] = ratingVal;
    
    // Get game title
    std::string gameTitle = "Unknown";
    for (const auto &gm : games) {
        if (gm.id == gameId) {
            gameTitle = gm.title;
            break;
        }
    }
    
    return "250 Rate success - You rated \"" + gameTitle + "\" " + std::to_string(ratingVal) + "/10.";
}

std::string handleRating(const std::vector<Game> &games, int gameId) {
    // Find the game by ID
    for (const auto &game : games) {
        if (game.id == gameId) {
            return "250 ESRB Rating for \"" + game.title + "\" is " + game.esrb;
        }
    }
    
    return "404 Game not found";
}

// Authentication functions
std::string handleUser(const std::string &username, bool &authenticated, std::string &currentUser, bool &closeConnection) {
    std::lock_guard<std::mutex> lock(credentialMutex);
    
    // Convert username to lowercase
    std::string lowercaseUsername = username;
    std::transform(lowercaseUsername.begin(), lowercaseUsername.end(), lowercaseUsername.begin(), 
                 [](unsigned char c){ return std::tolower(c); });
    
    currentUser = lowercaseUsername;
    authenticated = false;
    closeConnection = false;
    
    auto it = userCredentials.find(lowercaseUsername);
    
    if (it != userCredentials.end()) {
        // Existing user - reset failed attempts
        it->second.failedAttempts = 0;
        return "300 Password required";
    } else {
        // New user - create account with generated password
        try {
            // Generate random password
            std::string userPassword = generate_password();
            
            // Generate salt and hash
            auto salt = generate_salt();
            auto hash = hash_password(userPassword, salt);
            
            // Convert to base64
            std::string salt_b64 = base64_encode(salt.data(), salt.size());
            std::string hash_b64 = base64_encode(hash.data(), hash.size());
            
            // Store credential
            UserCredential cred;
            cred.username = lowercaseUsername;
            cred.salt = salt_b64;
            cred.hash = hash_b64;
            cred.failedAttempts = 0;
            
            userCredentials[lowercaseUsername] = cred;
            
            // Save to disk
            if (!save_credentials()) {
                return "500 INTERNAL SERVER ERROR - Failed to save credentials";
            }
            
            // Close connection after sending response
            closeConnection = true;
            
            return "230 New user created. Your password is: " + userPassword;
        }
        catch (const std::exception& e) {
            return "500 INTERNAL SERVER ERROR - Exception during registration";
        }
    }
}

std::string handlePass(const std::string &password, bool &authenticated, std::string &currentUser,
                     bool &browseMode, bool &rentMode, bool &myGamesMode, bool &closeConnection) {
    std::lock_guard<std::mutex> lock(credentialMutex);
    
    closeConnection = false;
    
    // Verify user exists
    auto it = userCredentials.find(currentUser);
    if (it == userCredentials.end()) {
        return "410 Authentication failed: User not found";
    }
    
    UserCredential &cred = it->second;
    
    // Check for account lockout
    if (cred.failedAttempts >= 2) {
        closeConnection = true;
        return "410 Authentication failed: too many invalid attempts";
    }
    
    try {
        // Decode salt and hash password
        auto salt_bin = base64_decode(cred.salt);
        auto hash = hash_password(password, salt_bin);
        std::string hash_b64 = base64_encode(hash.data(), hash.size());
        
        // Compare with stored hash
        if (hash_b64 == cred.hash) {
            // Successful login
            authenticated = true;
            cred.failedAttempts = 0;
            
            // Reset modes
            browseMode = false;
            rentMode = false;
            myGamesMode = false;
            
            return "210 Authentication successful";
        } else {
            // Failed authentication
            cred.failedAttempts++;
            authenticated = false;
            
            // Lock account after 2 failures
            if (cred.failedAttempts >= 2) {
                closeConnection = true;
            }
            
            return "410 Authentication failed: Invalid password";
        }
    } catch (const std::exception& e) {
        return "500 INTERNAL SERVER ERROR - Exception during authentication";
    }
}

// Main command handler
std::string processCommand(const std::string &command,
                         const std::string &clientAddr,
                         bool &authenticated,
                         bool &browseMode,
                         bool &rentMode,
                         bool &myGamesMode,
                         std::vector<Game> &games,
                         std::string &currentUser,
                         bool &closeConnection) {
    closeConnection = false;
    
    // Empty command check
    if (command.empty()) {
        return "400 BAD REQUEST - Empty command";
    }
    
    // Handle authentication commands
    if (command.rfind("USER ", 0) == 0) {
        return handleUser(command.substr(5), authenticated, currentUser, closeConnection);
    } 
    else if (command.rfind("PASS ", 0) == 0) {
        return handlePass(command.substr(5), authenticated, currentUser, browseMode, rentMode, myGamesMode, closeConnection);
    }
    
    // HELP is always available
    if (command == "HELP") {
        return handleHelp(browseMode, rentMode, myGamesMode);
    }
    
    // All other commands require authentication
    if (!authenticated) {
        return "403 FORBIDDEN - Not authenticated. Please login first with USER and PASS.";
    }
    
    // Mode switching commands
    if (command == "BROWSE") {
        browseMode = true;
        rentMode = false;
        myGamesMode = false;
        return "210 Switched to Browse Mode";
    }
    else if (command == "RENT") {
        browseMode = false;
        rentMode = true;
        myGamesMode = false;
        return "220 Switched to Rent Mode";
    }
    else if (command == "MYGAMES") {
        browseMode = false;
        rentMode = false;
        myGamesMode = true;
        return "230 Switched to MyGames Mode";
    }
    else if (command == "BYE") {
        return "200 BYE";
    }
    
    // Mode validation
    if (!browseMode && !rentMode && !myGamesMode) {
        return "503 Bad sequence of commands. Please enter a mode first (BROWSE, RENT, or MYGAMES).";
    }
    
    // BROWSE mode commands
    if (browseMode) {
        if (command.rfind("LIST", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd, filter;
            ss >> cmd >> filter;
            return handleList(games, filter);
        }
        else if (command.rfind("SEARCH", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd, filterType;
            ss >> cmd >> filterType;
            
            std::string filterValue;
            std::getline(ss >> std::ws, filterValue);
            
            if (filterType.empty() || filterValue.empty()) {
                return "400 BAD REQUEST - SEARCH requires filter and keyword.";
            }
            
            return handleSearch(games, filterType, filterValue);
        }
        else if (command.rfind("SHOW", 0) == 0) {
            return handleShow(games, command);
        }
    }
    
    // RENT mode commands
    else if (rentMode) {
        if (command.rfind("CHECKOUT ", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd;
            int gameId;
            ss >> cmd >> gameId;
            return handleCheckout(currentUser, gameId, games);
        }
        else if (command.rfind("RETURN ", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd;
            int gameId;
            ss >> cmd >> gameId;
            return handleReturn(currentUser, gameId, games);
        }
    }
    
    // MYGAMES mode commands
    else if (myGamesMode) {
        if (command == "HISTORY") {
            return handleHistory(currentUser, games);
        }
        else if (command.rfind("RECOMMEND", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd, filter;
            ss >> cmd >> filter;
            
            if (!filter.empty() && filter != "platform" && filter != "genre") {
                return "400 BAD REQUEST - Invalid filter. Use 'platform' or 'genre'.";
            }
            
            return handleRecommend(currentUser, games, filter);
        }
        else if (command.rfind("RATE ", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd;
            int gameId, rating;
            ss >> cmd >> gameId >> rating;
            return handleRate(currentUser, gameId, rating, games);
        }
        else if (command.rfind("RATING ", 0) == 0) {
            std::istringstream ss(command);
            std::string cmd;
            int gameId;
            ss >> cmd >> gameId;
            return handleRating(games, gameId);
        }
    }
    
    // If we get here, command was not recognized
    return "400 BAD REQUEST - Unknown command";
}

int main(int argc, char* argv[]) {
    // Check arguments
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

    // Load configuration
    std::string configFileName = argv[1];
    std::string port = getPortFromConfig(configFileName);
    if (port.empty()) {
        std::cerr << "Port number not found in configuration file" << std::endl;
        return 1;
    }

    // Initialize OpenSSL
    if (!init_openssl()) {
        std::cerr << "Failed to initialize OpenSSL" << std::endl;
        return 1;
    }

    // Load user credentials
    if (!load_credentials()) {
        std::cerr << "Failed to load user credentials" << std::endl;
        cleanup_openssl();
        return 1;
    }
    
    // Load games database
    std::vector<Game> games = loadGamesFromFile("games.db");
    
    // Setup server socket
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    int rv = getaddrinfo(nullptr, port.c_str(), &hints, &servinfo);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        cleanup_openssl();
        return 1;
    }
    
    // Find a socket to bind to
    int sockfd;
    int yes = 1;
    
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("server: socket");
            continue;
        }
        
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("server: setsockopt");
            close(sockfd);
            continue;
        }
        
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("server: bind");
            close(sockfd);
            continue;
        }
        
        break;
    }
    
    freeaddrinfo(servinfo);
    
    if (p == nullptr) {
        std::cerr << "server: failed to bind" << std::endl;
        cleanup_openssl();
        return 1;
    }
    
    // Listen for connections
    if (listen(sockfd, BACKLOG) == -1) {
        perror("server: listen");
        cleanup_openssl();
        return 1;
    }
    
    // Set up signal handlers
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("server: sigaction");
        cleanup_openssl();
        return 1;
    }
    
    // Set up termination handlers
    struct sigaction term_sa;
    term_sa.sa_handler = terminate_handler;
    sigemptyset(&term_sa.sa_mask);
    term_sa.sa_flags = 0;
    if (sigaction(SIGINT, &term_sa, nullptr) == -1 || 
        sigaction(SIGTERM, &term_sa, nullptr) == -1) {
        perror("server: termination sigaction");
        cleanup_openssl();
        return 1;
    }
    
    // Server startup complete
    std::cout << "=======================================================" << std::endl;
    std::cout << "Server listening on port " << port << std::endl;
    std::cout << "Loaded " << userCredentials.size() << " users and " << games.size() << " games" << std::endl;
    std::cout << "=======================================================" << std::endl;
    
    // Main accept loop
    while (true) {
        struct sockaddr_storage client_addr;
        socklen_t sin_size = sizeof client_addr;
        
        int client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &sin_size);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }
        
        // Get client address
        char client_ip[INET6_ADDRSTRLEN];
        inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), 
                  client_ip, sizeof client_ip);
        
        logEvent("New connection from " + std::string(client_ip));
        
        // Handle client in a new thread
        std::thread([client_fd, client_ip, &games]() {
            std::string client_addr(client_ip);
            
            try {
                // Create SSL connection
                SSLConnection ssl_conn(client_fd);
                
                // Perform TLS handshake
                if (!ssl_conn.accept()) {
                    logEvent("TLS handshake failed with client: " + client_addr);
                    return;
                }
                
                logEvent("TLS handshake successful with client: " + client_addr);
                
                // Set up session state
                bool authenticated = false;
                bool browseMode = false;
                bool rentMode = false;
                bool myGamesMode = false;
                std::string currentUser;
                bool closeConnection = false;
                
                // Command processing loop
                while (true) {
                    // Read client command
                    std::array<char, MAXDATASIZE> buffer;
                    int bytes = ssl_conn.read(buffer.data(), buffer.size() - 1);
                    
                    if (bytes <= 0) {
                        logEvent("Client disconnected: " + client_addr);
                        break;
                    }
                    
                    // Process the command
                    buffer[bytes] = '\0';
                    std::string command(buffer.data());
                    
                    // Clean up command (remove trailing newlines)
                    if (!command.empty() && (command.back() == '\n' || command.back() == '\r')) {
                        command.pop_back();
                    }
                    if (!command.empty() && (command.back() == '\n' || command.back() == '\r')) {
                        command.pop_back();
                    }
                    
                    // Process command and get response
                    std::string response = processCommand(
                        command, client_addr,
                        authenticated, browseMode, rentMode, myGamesMode,
                        games, currentUser, closeConnection
                    );
                    
                    // Send response to client
                    std::string formatted_response = response + "\r\n";
                    int result = ssl_conn.write(formatted_response.c_str(), formatted_response.length());
                    
                    if (result <= 0) {
                        logEvent("Failed to send response to client: " + client_addr);
                        break;
                    }
                    
                    // Check if we need to close the connection
                    if (closeConnection || response.rfind("200 BYE", 0) == 0) {
                        logEvent("Closing connection with client: " + client_addr);
                        break;
                    }
                }
            } 
            catch (const std::exception& e) {
                std::cerr << "Exception in client thread: " << e.what() << std::endl;
            }
            
            // Connection cleanup handled by SSLConnection destructor
        }).detach();
    }
    
    // Clean up (though we should never get here due to signal handlers)
    cleanup_openssl();
    return 0;
}