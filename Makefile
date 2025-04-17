CXX = g++
CXXFLAGS = -std=c++20 -Wall
# OpenSSL flags for Apple Silicon Mac with Homebrew
OPENSSL_FLAGS = -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

all: server client

server: server.cpp
	    $(CXX) $(CXXFLAGS) -o server server.cpp $(OPENSSL_FLAGS)

client: client.cpp
	    $(CXX) $(CXXFLAGS) -o client client.cpp $(OPENSSL_FLAGS)

clean:
	    rm -f server client
