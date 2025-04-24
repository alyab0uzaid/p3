CXX = g++
CXXFLAGS = -std=c++20 -Wall
# OpenSSL flags for Apple Silicon Mac with Homebrew
OPENSSL_FLAGS = -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto
# Add ncurses flags
NCURSES_FLAGS = -lncurses

all: server tui_client

server: server.cpp
	    $(CXX) $(CXXFLAGS) -o server server.cpp $(OPENSSL_FLAGS)

client: client.cpp
	    @echo "Skipping client build as it's not needed for submission"
	    # $(CXX) $(CXXFLAGS) -o client client.cpp $(OPENSSL_FLAGS)

test_client: test_client.cpp
	    $(CXX) $(CXXFLAGS) -o test_client test_client.cpp $(OPENSSL_FLAGS)

tui_client: tui_client.cpp
	    $(CXX) $(CXXFLAGS) -o tui_client tui_client.cpp $(OPENSSL_FLAGS) $(NCURSES_FLAGS)

clean:
	    rm -f server client test_client tui_client
