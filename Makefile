CXX = g++
CXXFLAGS = -std=c++20 -Wall
# OpenSSL flags for Apple Silicon Mac with Homebrew
OPENSSL_FLAGS = -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

all: server

server: server.cpp
	    $(CXX) $(CXXFLAGS) -o server server.cpp $(OPENSSL_FLAGS)

client: client.cpp
	    @echo "Skipping client build as it's not needed for submission"
	    # $(CXX) $(CXXFLAGS) -o client client.cpp $(OPENSSL_FLAGS)

test_client: test_client.cpp
	    $(CXX) $(CXXFLAGS) -o test_client test_client.cpp $(OPENSSL_FLAGS)

clean:
	    rm -f server client
