#include <bits/stdc++.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <unordered_map>
#include <iomanip>
#include <sys/select.h>
#include <unistd.h>
#include <sys/time.h>  // For timeout setting
#include <poll.h>

using namespace std;

#define GA_PORT 8081
#define SERVER_PORT 8084

#define DELIMITER "|"
#define AES_KEY_SIZE 16  // 128-bit key
#define AES_BLOCK_SIZE 16

const int CLIENTS = 3;
const int THRESHOLD = 2;

int server_fdd;
// Map to store RSA public keys of clients
map<int, EVP_PKEY*> clientPublicKeys;
vector<unsigned char> iv(16,0);   // 128-bit IV

// Function to generate a random key/IV
vector<unsigned char> generateRandomBytes(size_t size) {
    vector<unsigned char> buffer(size);
    RAND_bytes(buffer.data(), buffer.size());
    return buffer;
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to get SHA-256 hash of a message
vector<unsigned char> sha256Hash(const string& message) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char*)message.c_str(), message.size(), hash.data());
    return hash;
}

// Function to generate an RSA key pair
EVP_PKEY* generateRSAKeyPair() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (!rsa) handleErrors();
    EVP_PKEY_assign_RSA(pkey, rsa);
    return pkey;
}


// RSA Encryption (Public Key)
vector<unsigned char> rsaEncrypt(EVP_PKEY* publicKey, const vector<unsigned char>& plaintext) {
    size_t keySize = EVP_PKEY_get_size(publicKey);
    size_t chunkSize = keySize - 42;  // RSA-OAEP padding
    vector<unsigned char> encryptedData;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if (!ctx) handleErrors();

    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    for (size_t i = 0; i < plaintext.size(); i += chunkSize) {
        vector<unsigned char> chunk(plaintext.begin() + i, plaintext.begin() + min(i + chunkSize, plaintext.size()));
        size_t outlen;
        
        EVP_PKEY_encrypt(ctx, nullptr, &outlen, chunk.data(), chunk.size());
        vector<unsigned char> encryptedChunk(outlen);
        EVP_PKEY_encrypt(ctx, encryptedChunk.data(), &outlen, chunk.data(), chunk.size());

        encryptedData.insert(encryptedData.end(), encryptedChunk.begin(), encryptedChunk.end());
    }

    EVP_PKEY_CTX_free(ctx);
    return encryptedData;
}

// RSA Decryption (Private Key)
vector<unsigned char> rsaDecrypt(EVP_PKEY* privateKey, const vector<unsigned char>& ciphertext) {
    size_t keySize = EVP_PKEY_get_size(privateKey);
    vector<unsigned char> decryptedData;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) handleErrors();

    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    for (size_t i = 0; i < ciphertext.size(); i += keySize) {
        vector<unsigned char> chunk(ciphertext.begin() + i, ciphertext.begin() + min(i + keySize, ciphertext.size()));
        size_t outlen;
        
        EVP_PKEY_decrypt(ctx, nullptr, &outlen, chunk.data(), chunk.size());
        vector<unsigned char> decryptedChunk(outlen);
        EVP_PKEY_decrypt(ctx, decryptedChunk.data(), &outlen, chunk.data(), chunk.size());

        decryptedChunk.resize(outlen);
        decryptedData.insert(decryptedData.end(), decryptedChunk.begin(), decryptedChunk.end());
    }

    EVP_PKEY_CTX_free(ctx);
    return decryptedData;
}

// RSA Signing (Private Key)
vector<unsigned char> rsaSign(EVP_PKEY* privateKey, const vector<unsigned char>& messageHash) {
    size_t keySize = EVP_PKEY_get_size(privateKey);
    vector<unsigned char> signature(keySize);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) handleErrors();

    EVP_PKEY_sign_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

    size_t outlen = keySize;
    EVP_PKEY_sign(ctx, signature.data(), &outlen, messageHash.data(), messageHash.size());

    EVP_PKEY_CTX_free(ctx);
    return signature;
}

// RSA Verification (Public Key)
bool rsaVerify(EVP_PKEY* publicKey, const vector<unsigned char>& messageHash, const vector<unsigned char>& signature) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if (!ctx) handleErrors();

    EVP_PKEY_verify_recover_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

    vector<unsigned char> recoveredHash(SHA256_DIGEST_LENGTH);
    size_t outlen = SHA256_DIGEST_LENGTH;
    
    if (EVP_PKEY_verify_recover(ctx, recoveredHash.data(), &outlen, signature.data(), signature.size()) > 0) {
        EVP_PKEY_CTX_free(ctx);
        return (recoveredHash == messageHash);
    }

    EVP_PKEY_CTX_free(ctx);
    return false;
}

vector<unsigned char> encryptAES(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Failed to create EVP_CIPHER_CTX" << endl;
        exit(1);
    }

    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

vector<unsigned char> decryptAES(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error: Failed to create EVP_CIPHER_CTX" << endl;
        exit(1);
    }

    vector<unsigned char> decrypted(ciphertext.size());
    int len = 0, decrypted_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size());
    decrypted_len = len;
    EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
    decrypted_len += len;
    decrypted.resize(decrypted_len);

    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

// Store received RSA public key from a client
void storeClientPublicKey(int clientID, EVP_PKEY* pubKey) {
    clientPublicKeys[clientID] = pubKey;
}

// Receive a client's RSA public key
EVP_PKEY* receiveClientPublicKey(int client_fd) {
    BIO *bio = BIO_new(BIO_s_mem());
    char buffer[2048];

    int len = recv(client_fd, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        cerr << "Error receiving client's public key!" << endl;
        return nullptr;
    }

    BIO_write(bio, buffer, len);
    EVP_PKEY* clientKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return clientKey;
}

// Generate a random AES key
vector<unsigned char> generateAESKey() {
    vector<unsigned char> key(AES_KEY_SIZE);
    RAND_bytes(key.data(), AES_KEY_SIZE);
    return key;
}

// Polynomial evaluation for Shamir's Secret Sharing
int evaluatePolynomial(const vector<int>& coeffs, int x, int prime) {
    int result = 0;
    int power = 1;
    for (int coeff : coeffs) {
        result = (result + coeff * power) % prime;
        power = (power * x) % prime;
    }
    return result;
}

// Split key into n shares using Shamir's Secret Sharing
vector<pair<int, vector<unsigned char> > > splitKey(const vector<unsigned char>& key) {
    const int prime = 257;
    vector<pair<int, vector<unsigned char> > > shares;
    
    for (int i = 0; i < CLIENTS; ++i) {
        shares.emplace_back(i + 1, vector<unsigned char>(AES_KEY_SIZE));
    }

    for (int i = 0; i < AES_KEY_SIZE; ++i) {
        vector<int> coeffs(THRESHOLD);
        coeffs[0] = key[i];

        for (int j = 1; j < THRESHOLD; ++j) {
            coeffs[j] = rand() % prime;
        }

        for (int j = 0; j < CLIENTS; ++j) {
            shares[j].second[i] = evaluatePolynomial(coeffs, shares[j].first, prime);
        }
    }
    return shares;
}
// Reconstruct key from k shares
// Function to compute modular inverse using Fermat’s Little Theorem
int modInverse(int a, int prime) {
    int res = 1, exponent = prime - 2;
    while (exponent) {
        if (exponent % 2) res = (res * a) % prime;
        a = (a * a) % prime;
        exponent /= 2;
    }
    return res;
}

// Reconstruct key from k shares
vector<unsigned char> reconstructKey(const vector<pair<int, vector<unsigned char> > >& shares) {
    const int prime = 257;
    vector<unsigned char> key(AES_KEY_SIZE);

    for (int i = 0; i < AES_KEY_SIZE; ++i) {
        int result = 0;
        for (int j = 0; j < shares.size(); ++j) {
            int num = 1, den = 1;
            for (int k = 0; k < shares.size(); ++k) {
                if (j != k) {
                    num = (num * (-shares[k].first + prime)) % prime;
                    den = (den * (shares[j].first - shares[k].first + prime)) % prime;
                }
            }
            int lagrange_coeff = (num * modInverse(den, prime)) % prime;
            result = (result + (shares[j].second[i] * lagrange_coeff) % prime) % prime;
        }
        key[i] = result;
    }
    return key;
}

// Connect to the main server and send encrypted group files
int connectToMainServer() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Error creating socket to connect to main server." << endl;
        return -1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection to main server failed!" << endl;
        close(server_fd);
        return -1;
    }

    cout << "Connected to main server.\n";

    return server_fd;
}

//code for reconstructing the key

vector<unsigned char> reconstructKeyFromShares(const vector<int>& client_fds, int ga_fd) {
    vector<pair<int, vector<unsigned char> > > received_shares;
    fd_set readfds;
    int max_fd = ga_fd;
    for (int client_fd : client_fds) {
        max_fd = max(max_fd, client_fd);
    }

    // Polling for receiving shares from clients
    cout << "Waiting for clients to return shares...\n";

    // Notify clients to send their key shares
    for (int client_fd : client_fds) {
        string message = "Please send your AES key share.";
        send(client_fd, message.c_str(), message.size(), 0);
        cout << "Sent request to Client " << client_fd << " to send their AES key share.\n";
    }

    struct timeval timeout;
    timeout.tv_sec = 30;  // Timeout after 10 seconds (adjust as needed)
    timeout.tv_usec = 0;

    while (received_shares.size() < THRESHOLD) {
        // Clear the readfds set and add our sockets
        FD_ZERO(&readfds);
        FD_SET(ga_fd, &readfds); // Adding GA's server fd
        for (int client_fd : client_fds) {
            FD_SET(client_fd, &readfds);
        }

        // Wait for data on any of the client sockets with a timeout
        int activity = select(max_fd + 1, &readfds, nullptr, nullptr, &timeout);

        if (activity < 0) {
            cerr << "select() failed!" << endl;
            break;
        }
        else if (activity == 0) {
            // Timeout occurred, no data received from clients
            cout << "Timeout reached! Not all shares received. Exiting.\n";
            break;
        }

        // Check for each socket
        for (int i = 0; i < client_fds.size(); ++i) {
            int client_fd = client_fds[i];
            if (FD_ISSET(client_fd, &readfds)) {
                // We have data from this client
                vector<unsigned char> received_share(AES_KEY_SIZE);
                int bytesReceived = recv(client_fd, received_share.data(), AES_KEY_SIZE, 0);
                if (bytesReceived > 0) {
                    received_shares.emplace_back(i + 1, received_share);
                    cout << "Received AES key share from Client " << i + 1 << endl;
                }
//                else {
//                    cout << "Client " << i + 1 << " failed to send a key share.\n";
//                }
            }
        }
    }

    if (received_shares.size() < THRESHOLD) {
        // If not enough shares received, notify the clients that the process failed
//        for (int client_fd : client_fds) {
//            string error_message = "Key share reconstruction failed due to insufficient shares.";
//            send(client_fd, error_message.c_str(), error_message.size(), 0);
//        }

        cout << "Not enough shares received. Reconstruction failed.\n";
        return vector<unsigned char>();    }

    // Reconstruct the key from the received shares
    return reconstructKey(received_shares);
}

// Convert vector to string
string vectorToString(const vector<unsigned char>& vec) {
    return string(vec.begin(), vec.end());
}


// Function to split a string based on a delimiter
vector<string> splitString(const string &str, const string &delimiter) {
    vector<string> tokens;
    size_t start = 0, end;
    while ((end = str.find(delimiter, start)) != string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(str.substr(start)); // Last part
    return tokens;
}



// TCP Server setup
void runServer(const vector<pair<int, vector<unsigned char> > >& shares) {
    
    // Generate RSA Key Pair
    EVP_PKEY* keyPair = generateRSAKeyPair();
    EVP_PKEY* ga_public_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(ga_public_key, RSAPublicKey_dup(EVP_PKEY_get0_RSA(keyPair)));

    EVP_PKEY* ga_private_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(ga_private_key, RSAPrivateKey_dup(EVP_PKEY_get0_RSA(keyPair)));
    
    cout<<"exit of generation"<<endl;
    
    // rsa key exchange between ga and server (if not added in main function)
    // server:Receive key length first
    uint32_t serverkeySize;
    recv(server_fdd, &serverkeySize, sizeof(serverkeySize), 0);
    serverkeySize = ntohl(serverkeySize);  // Convert from network to host byte order

    // Receive the actual public key
    char* serverPubKeyBuf = new char[serverkeySize + 1]();  // Allocate exact memory
    recv(server_fdd, serverPubKeyBuf, serverkeySize, 0);
    serverPubKeyBuf[serverkeySize] = '\0';  // Null-terminate for safety

    // Convert received key back to EVP_PKEY*
    BIO* serverBio = BIO_new_mem_buf(serverPubKeyBuf, -1);
    EVP_PKEY* serverPublicKey = PEM_read_bio_PUBKEY(serverBio, nullptr, nullptr, nullptr);

    // Cleanup
    BIO_free(serverBio);
    delete[] serverPubKeyBuf;  // Free dynamically allocated memory

    if (!serverPublicKey) {
        cerr << "Failed to parse server's public key!" << endl;
        return ;
    }

    cout << "Server's public key received successfully!" << endl;
    
    //sending key to server
    // Convert publicKey to PEM format and sending public key to the server
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, ga_public_key);
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    uint32_t keySize1 = htonl(pemLen);
    send(server_fdd, &keySize1, sizeof(keySize1), 0);
    send(server_fdd, pemData, pemLen, 0);
    BIO_free(bio);
    
    cout<<"Key size of the client: "<<keySize1<<endl;
    cout<<"GA send key to server "<<endl;
    
    //log 1
    
    //making it's own socket for connecting with clients
    int ga_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(ga_fd < 0) {
        cerr<<"error in server_fd\n";
        exit(1);
    }
    cout<<"ga-fd"<<" "<<ga_fd<<endl;
    struct sockaddr_in ga_addr;
    ga_addr.sin_family = AF_INET;
    ga_addr.sin_addr.s_addr = INADDR_ANY;
    ga_addr.sin_port = htons(GA_PORT);

    if(bind(ga_fd, (struct sockaddr*)&ga_addr, sizeof(ga_addr))<0){
        cerr<<"error in binding in ga\n";
        exit(1);
    };
    
    if(listen(ga_fd, 3)<0){
        cerr<<"error in listening in ga\n";
        exit(1);
    };
    cout << "GA is listening on port " << ntohs(ga_addr.sin_port) << endl;

    socklen_t len = sizeof(ga_addr);
    if (getsockname(ga_fd, (struct sockaddr*)&ga_addr, &len) == -1) {
        perror("getsockname failed");
    } else {
        cout << "Server is listening on port " << ntohs(ga_addr.sin_port) << endl;
    }

    cout << "Waiting for clients...\n";
    vector<int> client_fds;

    // Send shares to clients and exchange RSA public keys
    for (int i = 0; i < 3; ++i) {
        cout<<"loop wala"<<endl;
        int client_fd = accept(ga_fd, nullptr, nullptr);
        client_fds.push_back(client_fd);
        //sending public key to clients
        // Convert publicKey to PEM format and sending public key to the server
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, ga_public_key);
        char* pemData;
        long pemLen = BIO_get_mem_data(bio, &pemData);
        uint32_t keySize1 = htonl(pemLen);
        send(client_fd, &keySize1, sizeof(keySize1), 0);
        send(client_fd, pemData, pemLen, 0);
        BIO_free(bio);
        
        cout<<"Key size of the client: "<<keySize1<<endl;
        cout<<"GA send key to client "<<i<<endl;
        

        //receiving public key from client
        uint32_t clientkeySize;
        recv(client_fd, &clientkeySize, sizeof(clientkeySize), 0);
        clientkeySize = ntohl(clientkeySize);  // Convert from network to host byte order

        // Receive the actual public key
        char* clientPubKeyBuf = new char[clientkeySize + 1]();  // Allocate exact memory
        recv(client_fd, clientPubKeyBuf, clientkeySize, 0);
        clientPubKeyBuf[clientkeySize] = '\0';  // Null-terminate for safety

        // Convert received key back to EVP_PKEY*
        BIO* clientBio = BIO_new_mem_buf(clientPubKeyBuf, -1);
        EVP_PKEY* clientPublicKey = PEM_read_bio_PUBKEY(clientBio, nullptr, nullptr, nullptr);

        // Cleanup
        BIO_free(clientBio);
        delete[] clientPubKeyBuf;  // Free dynamically allocated memory

        if (!clientPublicKey) {
            cerr << "Failed to parse server's public key!" << endl;
            return;
        }

        cout << "client " <<i<< " public key received successfully!" << endl;

        if (clientPublicKey) {
            storeClientPublicKey(client_fd, clientPublicKey);
            cout << "Stored Client " << i + 1 << "'s Public Key." << endl;
        }

        // Send AES key share to client
        send(client_fd, shares[i].second.data(), AES_KEY_SIZE, 0);
        cout << "Sent AES key share to Client " << i + 1 << endl;
    }

    // Now process the request from the client
    cout << "Checking request type (store or retrieve)..." << endl;
    
    // storing client fds to poll fds
    vector<struct pollfd> poll_fds(client_fds.size());

    for (size_t i = 0; i < client_fds.size(); ++i) {
        poll_fds[i].fd = client_fds[i];
        poll_fds[i].events = POLLIN; // Check for incoming data
    }
    
    // **RECEIVING REQUEST FROM CLIENT**
    while(true){
        char requestBuffer[4096];
        int index_fd = -1;
        
        //polling for checking which client is ready to send the data
        int ready = poll(poll_fds.data(), poll_fds.size(), 5000); // 5s timeout

        if (ready < 0) {
            perror("poll failed");
            return;
        } else if (ready == 0) {
            cout << "No clients ready to send data." << endl;
            continue;
        }
        for (size_t i = 0; i < poll_fds.size(); ++i) {
            if (poll_fds[i].revents & POLLIN) {
                cout << "Client with FD " << poll_fds[i].fd << " is ready to send data." << endl;
                index_fd = i;
                break;
            }
        }
        
        if (index_fd == -1) continue;
        
    	//receiving data from the client     ================= but which client ???
        size_t totalSize;
        recv(poll_fds[index_fd].fd, &totalSize, sizeof(totalSize), 0); // Receive total size first

        vector<unsigned char> encryptedData(totalSize);
        size_t receivedBytes = 0;

        while (receivedBytes < totalSize) {
            size_t chunkSize = std::min((size_t)4096, totalSize - receivedBytes);
            ssize_t received = recv(poll_fds[index_fd].fd, encryptedData.data() + receivedBytes, chunkSize, 0);
            
            if (received <= 0) {
                cerr << "Error receiving data!" << endl;
                break;
            }
            
            receivedBytes += received;
        }
        cout << "Received " << receivedBytes << " bytes successfully." << endl;
        
        cout << "RSA Encrypted Data: ";
        for (auto c : encryptedData)
            cout << hex << setw(2) << setfill('0') << (int)c << " ";
        cout << endl;
        
        //receiving the size of the signature from the client
        uint32_t sigSize;
        recv(poll_fds[index_fd].fd, &sigSize, sizeof(sigSize), 0);
        cout<<"size of the signature generated: "<<sigSize<<endl;
        sigSize = ntohl(sigSize);  // Convert from network to host byte order
        
	    
	    // Call the new function to reconstruct the key
	    auto reconstructedKey = reconstructKeyFromShares(client_fds, ga_fd);
	    if(reconstructedKey.size()==0) continue;
	    cout << "Reconstructed AES Key: ";
	    for (unsigned char c : reconstructedKey) cout << hex << (int)c << " ";
	    cout << endl;
    
        
        // Step 7: Decrypt with Private Key of the GA ============ to modify
        vector<unsigned char> decryptedData = rsaDecrypt(ga_private_key, encryptedData);
        cout << "client wala mutu: "<<endl;
        for (unsigned char c : decryptedData) {
            cout << hex << setw(2) << setfill('0') << (int)c << " ";
        }

        string receivedMessage(decryptedData.begin(), decryptedData.end() - sigSize);
        vector<unsigned char> receivedSignature(decryptedData.end() - sigSize, decryptedData.end());
        
        cout << "Decrypted Message: " << receivedMessage << endl;
        
        vector<string> messageParts = splitString(receivedMessage, "||");
        
        // Step 8: Verify Hash with the public key of the client that has sent the message ======= modify
        vector<unsigned char> receivedHash = sha256Hash(receivedMessage);
        if (rsaVerify(clientPublicKeys[client_fds[index_fd]], receivedHash, receivedSignature)) {
            cout << "✅ Signature Verification Passed!" << endl;
        } else {
            cout << "❌ Signature Verification Failed!" << endl;
        }
        
        // Further split receivedData on '||'
        vector<string> parts = splitString(receivedMessage, "||");
        int delimiterCount = parts.size() - 1;
        cout<<"delimiterCount: "<<delimiterCount<<endl;
        

	    if (delimiterCount == 2) {  // store on the server   (fu)
            cout << "Detected STORE request (delimiter count == 3)\n";
            
            string message;
            vector<unsigned char> hash = sha256Hash(parts[0]);  //generating the hash of the original content of the whole file
            cout << "Computed SHA-256 Hash of original content : " << vectorToString(hash) << endl; //hf

            // Encrypt the message
            vector<unsigned char> plaintext(parts[0].begin(), parts[0].end()); //encrypting the content with the aes key
            vector<unsigned char> ciphertext = encryptAES(plaintext, reconstructedKey, iv);   //ef
            
            string filename=parts[1];
            string user_name=parts[2];
            
            message+=vectorToString(ciphertext); //ef
            message+="||";    //ef ||
            message+=vectorToString(hash); // ef||hf
            message+="||";   //ef||hf||
            message+=filename; //ef||hf||filename
            message+="||";   // ef||hf||filename||
            message+=user_name;  // meessage = [ef||hf||filename||username]
            
            // Step 3: Compute Hash of the whole message for generating the signature
            hash = sha256Hash(message);
            cout << "Computed SHA-256 of whole message Hash: " << vectorToString(hash) << endl;
            
            //sign the hash with private key of the GA =============== ga ka private key se sign kro
            vector<unsigned char> signature = rsaSign(ga_private_key, hash);
            cout << "Digital Signature: " << vectorToString(signature) << endl;
            

            // Step 5: Append Signature to Message
            vector<unsigned char> messageWithSignature(message.begin(), message.end());
            messageWithSignature.insert(messageWithSignature.end(), signature.begin(), signature.end());
            cout << "Decrypted before ecncryption hai mutu"<<endl;
            for (unsigned char c : messageWithSignature) {
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            }
            
            // Step 6: Encrypt with Public Key of server
            vector<unsigned char> encryptedMessage = rsaEncrypt(serverPublicKey, messageWithSignature);
            cout<<"Encrypted message from the client side minati: "<<endl;
            for (auto c : encryptedMessage)
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            cout << endl;
            
            //send request to the server
            size_t totalSize = encryptedMessage.size();
            send(server_fdd, &totalSize, sizeof(totalSize), 0); // Send total size first

            size_t sentBytes = 0;
            while (sentBytes < totalSize) {
                size_t chunkSize = std::min((size_t)4096, totalSize - sentBytes);
                ssize_t sent = send(server_fdd, encryptedMessage.data() + sentBytes, chunkSize, 0);
                
                if (sent <= 0) {
                    cerr << "Error sending data!" << endl;
                    break;
                }
                
                sentBytes += sent;
            }
            cout << "Sent " << sentBytes << " bytes successfully." << endl;
        //    send(client_fd, encryptedMessage.data(), encryptedMessage.size(), 0);
            cout << "Sent encrypted file data to server." << endl;
            
            // Send signature size
            uint32_t sigSize = htonl(signature.size());
            send(server_fdd, &sigSize, sizeof(sigSize), 0);
            cout<<"The size of the signature sent from the client: "<<sigSize<<endl;
            
        }
        
        
        
        
        
        else {  // RETRIEVE data from the server
            cout << "Detected RETRIEVE request (delimiter count ≤ 1)\n";
            
            //retrieval part
            string user_id=parts[0];
            string filename=parts[1];
            string retrieve_request = user_id + "||" + filename;
            
            vector<unsigned char> hash1;

            // Step 3: Compute Hash of the whole message to send to server
            hash1 = sha256Hash(retrieve_request);
            cout << "Computed SHA-256 Hash: " << vectorToString(hash1) << endl;
            
            //sign the hash with private key of GA ========== modify
            vector<unsigned char> signature1 = rsaSign(ga_private_key, hash1);
            cout << "Digital Signature: " << vectorToString(signature1) << endl;
            

            // Step 5: Append Signature to Message
            vector<unsigned char> messageWithSignature1(retrieve_request.begin(), retrieve_request.end());
            messageWithSignature1.insert(messageWithSignature1.end(), signature1.begin(), signature1.end());
            cout << "Decrypted before ecncryption hai mutu"<<endl;
            for (unsigned char c : messageWithSignature1) {
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            }
            
            // Step 6: Encrypt with Public Key of server
            vector<unsigned char> encryptedMessage1 = rsaEncrypt(serverPublicKey, messageWithSignature1);
            cout<<"Encrypted message from the client side minati: "<<endl;
            for (auto c : encryptedMessage1)
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            cout << endl;
            //yaha tak kaam karaha hai
            
        //    cout << "Encrypted Message: " << vectorToString(encryptedMessage) << endl;

            
            
            
            
            
            
            // Send Encrypted Data to Server
            size_t totalSize1 = encryptedMessage1.size();
            send(server_fdd, &totalSize1,sizeof(totalSize1), 0); // Send total size first

            size_t sentBytes1 = 0;
            while (sentBytes1 < totalSize1) {
                size_t chunkSize = std::min((size_t)4096, totalSize1 - sentBytes1);
                ssize_t sent = send(server_fdd, encryptedMessage1.data() + sentBytes1, chunkSize, 0);
                
                if (sent <= 0) {
                    cerr << "Error sending data!" << endl;
                    break;
                }
                
                sentBytes1 += sent;
            }
            cout << "Sent " << sentBytes1 << " bytes successfully." << endl;
        //    send(client_fd, encryptedMessage.data(), encryptedMessage.size(), 0);
            cout << "Sent encrypted file data to server." << endl;
            
            // Send signature size
            uint32_t sigSize1 = htonl(signature1.size());
            send(server_fdd, &sigSize1, sizeof(sigSize1), 0);
            cout<<"The size of the signature sent from the client: "<<sigSize<<endl;
            
            
            
            
            
            
            //receiving the size of the signature from the server
            uint32_t sigSize2;
            recv(server_fdd, &sigSize2, sizeof(sigSize2), 0);
            cout<<"The signature size received from the server is: "<<sigSize2<<endl;
            sigSize2 = ntohl(sigSize2);  // Convert from network to host byte order
            
            //receiving the size of data from the server
            size_t totalSize4;
            recv(server_fdd, &totalSize4, sizeof(totalSize4), 0); // Receive total size first

            vector<unsigned char> encryptedData4(totalSize4);
            size_t receivedBytes = 0;

            while (receivedBytes < totalSize4) {
                size_t chunkSize = std::min((size_t)4096, totalSize4 - receivedBytes);
                ssize_t received = recv(server_fdd, encryptedData4.data() + receivedBytes, chunkSize, 0);
                
                if (received <= 0) {
                    cerr << "Error receiving data!" << endl;
                    break;
                }
                
                receivedBytes += received;
            }
            cout << "Received " << receivedBytes << " bytes successfully." << endl;
            cout<<"dallu don"<<endl;
            cout<<"PRINTING THE ENCRYPTED DATA RECEIVED WITHOUT DECRYPTION"<<endl;
            for (auto c : encryptedData4)
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            cout << endl;

            
            
            //now the decryption part of the retrieved file
            // Step 7: Decrypt with Private Key
            cout<<"decryption part suru"<<endl;    // ===== decrypt with private key of GA
            vector<unsigned char> decryptedData4 = rsaDecrypt(ga_private_key, encryptedData4);
            string receivedMessage(decryptedData4.begin(), decryptedData4.end() - sigSize2);
            vector<unsigned char> receivedSignature(decryptedData4.end() - sigSize2, decryptedData4.end());
            cout<<"ab dekh yaha pe"<<endl;

            cout << "Decrypted Message: " << receivedMessage << endl;
            
            vector<string> messageParts = splitString(receivedMessage, "||");
            
            // Step 9: Print the extracted values
            cout<<"chalo receive karte hain"<<endl;
            cout << "\nExtracted Parts:\n";
            cout << "1. Original Message: " << messageParts[0] << endl;
            cout << "2. Computed SHA-256 Hash: " << messageParts[1] << endl;
            cout << "3. File Name: " << messageParts[2] << endl;
            cout << "4. User ID: " << messageParts[3] << endl;
            
             //Step 8: Verify Hash ====== check the key i think it is correct
            vector<unsigned char> receivedHash = sha256Hash(receivedMessage);
            if (rsaVerify(serverPublicKey, receivedHash, receivedSignature)) {
                cout << "✅ Signature Verification Passed!" << endl;
            } else {
                cout << "❌ Signature Verification Failed!" << endl;
            }
            
            
            
            
            

            // decrypting the original message so that we do not need to send the aes key to any client
            vector<unsigned char> cipher(messageParts[0].begin(),messageParts[0].end() );
            vector<unsigned char> plaintext = decryptAES(cipher, reconstructedKey, iv);   //ef
            
            string message(plaintext.begin(),plaintext.end());
            cout<<"\n\n decrypted aes message is => "<<message<<endl;
            message+="||";
            message+=messageParts[2];
            message+="||";
            message+=messageParts[3];
            
            // Step 3: Compute Hash of the whole message
            vector<unsigned char> hash = sha256Hash(message);
            cout << "Computed SHA-256 Hash: " << vectorToString(hash) << endl;
            
            //sign the hash with private key of ga =========== ga private key
            vector<unsigned char> signature = rsaSign(ga_private_key, hash);
            cout << "Digital Signature: " << vectorToString(signature) << endl;
            

            // Step 5: Append Signature to Message
            vector<unsigned char> messageWithSignature(message.begin(), message.end());
            messageWithSignature.insert(messageWithSignature.end(), signature.begin(), signature.end());
            cout << "Decrypted before ecncryption hai mutu"<<endl;
            for (unsigned char c : messageWithSignature) {
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            }
            
            // Step 6: Encrypt with Public Key of the client that has sent the request   ========
            vector<unsigned char> encryptedMessage = rsaEncrypt(clientPublicKeys[client_fds[index_fd]], messageWithSignature);
            cout<<"Encrypted message from the client side minati: "<<endl;
            for (auto c : encryptedMessage)
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            cout << endl;
            //yaha tak kaam karaha hai
            
        //    cout << "Encrypted Message: " << vectorToString(encryptedMessage) << endl;

            // Send signature size
            uint32_t sigSize = htonl(signature.size());
            send(poll_fds[index_fd].fd, &sigSize, sizeof(sigSize), 0);
            cout<<"The size of the signature sent from the client: "<<sigSize<<endl;
            // Send Encrypted Data to client   ====== yahan pr client ki fd change krni hogi
            size_t totalSize = encryptedMessage.size();
            send(poll_fds[index_fd].fd, &totalSize, sizeof(totalSize), 0);
            cout<<endl;

            size_t sentBytes = 0;
            while (sentBytes < totalSize) {
                size_t chunkSize = std::min((size_t)4096, totalSize - sentBytes);
                ssize_t sent = send(poll_fds[index_fd].fd, encryptedMessage.data() + sentBytes, chunkSize, 0);
                
                if (sent <= 0) {
                    cerr << "Error sending data!" << endl;
                    break;
                }
                
                sentBytes += sent;
            }
            cout << "Sent " << sentBytes << " bytes successfully." << endl;
        //    send(client_fd, encryptedMessage.data(), encryptedMessage.size(), 0);
            cout << "Sent encrypted file data to server." << endl;
        
	    }
    }

    // Cleanup
    for (int fd : client_fds) close(fd);
    close(ga_fd);
}


int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    srand(time(nullptr));

    // Generate RSA Key Pair for GA
//    EVP_PKEY* gaKey = generateRSAKey();
    
    //connection with main server i.e server_fdd
    server_fdd = connectToMainServer();
    
    //here we have to add the code to send and receive rsa key from the server or in the run server function
    
    // Generate AES Key
    auto aesKey = generateAESKey();
    cout << "Generated AES Key: ";
    for (unsigned char c : aesKey) cout << hex << (int)c << " ";
    cout << endl;
    
    vector<unsigned char> iv = generateRandomBytes(16);   // 128-bit IV
    // Split AES Key into shares
    
    auto shares = splitKey(aesKey);

    // Run the server to handle clients
    runServer(shares);

    return 0;
}


