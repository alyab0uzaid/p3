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

// OpenSSL headers for TLS support
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

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
        out << "HELO <hostname>\n";
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
        out << "MYGAMES\n";
        out << "BROWSE\n";
        out << "HELP\n";
        out << "BYE\n";
    }
    else {
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

// handleCommand
std::string handleCommand(const std::string &command,
                          const std::string &clientAddr,
                          bool &heloSetup,
                          bool &browseMode,
                          bool &rentMode,
                          bool &myGamesMode,
                          std::vector<Game> &games) {

    // HELO must be sent first before any other command
    if (!heloSetup && command.rfind("HELO ", 0) != 0) {
        return "403 FORBIDDEN - HELO must be sent first.";
    }
    //HELO
    if (command.rfind("HELO ", 0) == 0) {
        std::string instance = command.substr(5);
        char hostname[1024];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            return "500 INTERNAL SERVER ERROR - Could not retrieve hostname";
        }
        if (instance == hostname) {
            heloSetup = true;
            return "200 HELO " + clientAddr + " (TCP)";
        } else {
            return "403 FORBIDDEN - Wrong server instance";
        }
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
            return handleCheckout(clientAddr, gID, games);
        }
        else if (command.rfind("RETURN ", 0) == 0) {
            //RETURN
            std::istringstream ss(command);
            std::string c;
            int gID;
            ss >> c >> gID;
            return handleReturn(clientAddr, gID, games);
        }
    }
    // MYGAMES commands
    if (myGamesMode) {
        if (command == "HISTORY") {
            //HISTORY
            return handleHistory(clientAddr, games);
        }
        else if (command.rfind("RECOMMEND", 0) == 0) {
            //RECOMMEND
            std::istringstream ss(command);
            std::string c, f;
            ss >> c >> f;
            if (!f.empty() && f != "platform" && f != "genre") {
                return "400 BAD REQUEST - Invalid filter. Use 'platform' or 'genre'.";
            }
            return handleRecommend(clientAddr, games, f);
        }
        else if (command.rfind("RATE ", 0) == 0) {
            //RATE
            std::istringstream ss(command);
            std::string c;
            int gID, val;
            ss >> c >> gID >> val;
            return handleRate(clientAddr, gID, val, games);
        }
    }
    //BYE
    if (command == "BYE") {
        return "200 BYE";
    }
    // fallback
    return "400 BAD REQUEST";
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

                bool heloSetup = false;
                bool browseMode = false;
                bool rentMode = false;
                bool myGamesMode = false;

                while (true) {
                    numbytes = ssl_conn.read(buf.data(), MAXDATASIZE - 1);
                    if (numbytes <= 0) {
                        if (numbytes < 0) {
                            std::cerr << "SSL read error" << std::endl;
                        }
                        logEvent("Client disconnected: " + clientAddress);
                        break;
                    }
                    
                    buf[numbytes] = '\0';
                    std::string received(buf.data());

                    std::string response = handleCommand(
                        received, clientAddress,
                        heloSetup, browseMode,
                        rentMode, myGamesMode,
                        games
                    );
                    
                    if (ssl_conn.write(response.c_str(), response.size()) <= 0) {
                        std::cerr << "SSL write error" << std::endl;
                        break;
                    }
                    
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
