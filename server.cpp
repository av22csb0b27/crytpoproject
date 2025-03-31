#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include<bits/stdc++.h>
#include<iomanip>
#include <openssl/rand.h>
#include <poll.h>

using namespace std;

#define SERVER_PORT 8084
#define DELIMITER "|"
#define AES_KEY_SIZE 16  // 128-bit key
#define AES_BLOCK_SIZE 16
#define server_id "server"
const size_t RSA_BLOCK_SIZE = 230; // 2048-bit RSA key block size

unordered_map<string, unordered_map<string, pair<string, string> > > data;

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

void printPublicKey(EVP_PKEY* pkey) {
    if (!pkey) {
        cout << "Public key is null!" << endl;
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        cerr << "Error writing public key" << endl;
        BIO_free(bio);
        return;
    }

    char* key_data;
    long key_len = BIO_get_mem_data(bio, &key_data);
    cout << "Public Key:\n" << string(key_data, key_len) << endl;

    BIO_free(bio);
}

void printPrivateKey(EVP_PKEY* pkey) {
    if (!pkey) {
        cout << "Private key is null!" << endl;
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        cerr << "Error writing private key" << endl;
        BIO_free(bio);
        return;
    }

    char* key_data;
    long key_len = BIO_get_mem_data(bio, &key_data);
    cout << "Private Key:\n" << string(key_data, key_len) << endl;

    BIO_free(bio);
}
// Convert vector to string
string vectorToString(const vector<unsigned char>& vec) {
    return string(vec.begin(), vec.end());
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Socket creation failed." << endl;
        return 1;
    }
    
    struct sockaddr_in server_addr, client_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Binding failed." << endl;
        return 1;
    }
    
    if (listen(server_fd, 5) < 0) {
        cerr << "Listening failed." << endl;
        return 1;
    }
    
    cout << "Server is listening on port " << SERVER_PORT << endl;
    
    socklen_t client_len = sizeof(client_addr);
    int client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_sock < 0) {
        cerr << "Connection to Client has failed." << endl;
        return 1;
    }
    
    cout << "Client Connected" << endl;
    
    //    RAND_poll();
    
    // Step 1: Generate RSA Key Pair
    EVP_PKEY* keyPair = generateRSAKeyPair();
    EVP_PKEY* serverpublicKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(serverpublicKey, RSAPublicKey_dup(EVP_PKEY_get0_RSA(keyPair)));
    
    EVP_PKEY* serverprivateKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(serverprivateKey, RSAPrivateKey_dup(EVP_PKEY_get0_RSA(keyPair)));
    
    //sending the servers public key to the client
    // Convert server's public key to PEM format
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, serverpublicKey);
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    
    // Send key length first of server public key
    uint32_t keySize1 = htonl(pemLen);
    send(client_sock, &keySize1, sizeof(keySize1), 0);
    
    // Send the actual public key
    send(client_sock, pemData, pemLen, 0);
    
    // Cleanup
    BIO_free(bio);
    
    //receiving public of client
    // Receive key length first of client public key
    uint32_t keySize2;
    recv(client_sock, &keySize2, sizeof(keySize2), 0);
    keySize2 = ntohl(keySize2);  // Convert from network to host byte order
    cout<<"The key size of the client is: "<<keySize2<<endl;
    
    // Receive the actual public key
    char* clientPubKeyBuf = new char[keySize2 + 1]();  // Allocate exact memory
    recv(client_sock, clientPubKeyBuf, keySize2, 0);
    clientPubKeyBuf[keySize2] = '\0';  // Null-terminate for safety
    
    // Convert received key back to EVP_PKEY*
    BIO* clientBio = BIO_new_mem_buf(clientPubKeyBuf, -1);
    EVP_PKEY* clientKey = PEM_read_bio_PUBKEY(clientBio, nullptr, nullptr, nullptr);
    
    // Cleanup
    BIO_free(clientBio);
    delete[] clientPubKeyBuf;  // Free dynamically allocated memory
    
    if (!clientKey) {
        cerr << "Failed to parse client's public key!" << endl;
        return 1;
    }
    
    cout << "Client's public key received successfully!" << endl;
    
    //calling the print function of the keys
    printPrivateKey(serverprivateKey);
    printPublicKey(serverpublicKey);
    
    //log 1
    
    //     Receive Encrypted Data
    struct pollfd fds[1]; // Only one file descriptor (GA connection)
    fds[0].fd = client_sock;  // GA socket
    fds[0].events = POLLIN;   // Wait for incoming data
    
    int i=0;
    while(i<2){
        int ret = poll(fds, 1, -1); // Wait indefinitely (-1) until data is available
        if (ret < 0) {
            cerr << "Error in poll()" << endl;
            break;
        }

        if(fds[0].revents & POLLIN){
            size_t totalSize;
            recv(client_sock, &totalSize, sizeof(totalSize), 0); // Receive total size first
            
            vector<unsigned char> encryptedData(totalSize);
            size_t receivedBytes = 0;
            
            while (receivedBytes < totalSize) {
                size_t chunkSize = std::min((size_t)4096, totalSize - receivedBytes);
                ssize_t received = recv(client_sock, encryptedData.data() + receivedBytes, chunkSize, 0);
                
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
            recv(client_sock, &sigSize, sizeof(sigSize), 0);
            cout<<"size of the signature generated: "<<sigSize<<endl;
            sigSize = ntohl(sigSize);  // Convert from network to host byte order
            
            // Step 7: Decrypt with Private Key
            vector<unsigned char> decryptedData = rsaDecrypt(serverprivateKey, encryptedData);
            cout << "client wala mutu: "<<endl;
            for (unsigned char c : decryptedData) {
                cout << hex << setw(2) << setfill('0') << (int)c << " ";
            }
            
            string receivedMessage(decryptedData.begin(), decryptedData.end() - sigSize);
            vector<unsigned char> receivedSignature(decryptedData.end() - sigSize, decryptedData.end());
            
            cout << "Decrypted Message: " << receivedMessage << endl;
            
            vector<string> messageParts = splitString(receivedMessage, "||");
            
            // Step 8: Verify Hash
            vector<unsigned char> receivedHash = sha256Hash(receivedMessage);
            if (rsaVerify(clientKey, receivedHash, receivedSignature)) {
                cout << "✅ Signature Verification Passed!" << endl;
            } else {
                cout << "❌ Signature Verification Failed!" << endl;
            }
            
            // Further split receivedData on '|'
            vector<string> parts = splitString(receivedMessage, "||");
            int delimiterCount = parts.size() - 1;
            cout<<"delimiterCount: "<<delimiterCount<<endl;
            
            // Determine request type based on delimiter count
            if (delimiterCount == 3) {
                cout << "Request Type: STORE" << endl;
                string ef = parts[0];
                string hf_received = parts[1];
                string user_id = parts[3];
                string filename = parts[2];
                
                cout << "Encrypted File (ef): "<<ef<<endl;
                
                // Store logic here
                data[user_id][filename] = std::pair<string, string>(ef, hf_received);
                cout<<"file stored successfully"<<endl;
                i++;
            } else if (delimiterCount == 1) {
                cout << "Request Type: RETRIEVE" << endl;
                string user_id = parts[0];
                string filename = parts[1];
                
                cout << "User ID: " << user_id << ", Filename: " << filename << endl;
                
                
                // Check if user_id has the requested file
                if (data.find(user_id) == data.end() || data[user_id].find(filename) == data[user_id].end()) {
                    cerr << "Error: File not found for user " << user_id << "!" << endl;
                    string errorMsg = "File not found";
                    send(client_sock, errorMsg.c_str(), errorMsg.size(), 0);
                    return 1;
                }
                
                // Retrieve file data and hash
                string ef = data[user_id][filename].first;
                string hf_received = data[user_id][filename].second;
                
                string message=ef;
                
                // Step 3: Compute Hash
                vector<unsigned char> hash = sha256Hash(message);
                cout << "Computed SHA-256 Hash: " << vectorToString(hash) << endl;
                
                message+="||";
                message+=vectorToString(hash);
                message+="||";
                message+=filename;
                message+="||";
                message+=user_id;
                
                hash = sha256Hash(message);
                cout << "Computed SHA-256 Hash: " << vectorToString(hash) << endl;
                
                //sign the hash with private key
                vector<unsigned char> signature = rsaSign(serverprivateKey, hash);
                cout << "Digital Signature: " << vectorToString(signature) << endl;
                
                //sending the size of the signature
                // Send signature size first
                uint32_t sigSize = htonl(signature.size());
                send(client_sock, &sigSize, sizeof(sigSize), 0);
                cout<<"Signature sent from the server side size: "<<sigSize<<endl;
                
                // Step 5: Append Signature to Message
                vector<unsigned char> messageWithSignature(message.begin(), message.end());
                messageWithSignature.insert(messageWithSignature.end(), signature.begin(), signature.end());
                
                // Step 6: Encrypt with Public Key
                vector<unsigned char> encryptedMessage = rsaEncrypt(clientKey, messageWithSignature);
                //            cout << "Encrypted Message: " << vectorToString(encryptedMessage) << endl;
                cout<<"Encrypted message from the server side minati: "<<endl;
                for (auto c : encryptedMessage)
                    cout << hex << setw(2) << setfill('0') << (int)c << " ";
                cout << endl;
                
                
                
                
                // Send Encrypted Data to client
                size_t totalSize = encryptedMessage.size();
                send(client_sock, &totalSize, sizeof(totalSize), 0); // Send total size first
                
                size_t sentBytes = 0;
                while (sentBytes < totalSize) {
                    size_t chunkSize = std::min((size_t)4096, totalSize - sentBytes);
                    ssize_t sent = send(client_sock, encryptedMessage.data() + sentBytes, chunkSize, 0);
                    
                    if (sent <= 0) {
                        cerr << "Error sending data!" << endl;
                        break;
                    }
                    
                    sentBytes += sent;
                }
                cout << "Sent " << sentBytes << " bytes successfully." << endl;
                
                
                //    send(client_fd, encryptedMessage.data(), encryptedMessage.size(), 0);
                cout << "Sent encrypted file data to client." << endl;
                
                
            }
        }
    }
    close(client_sock);
    close(server_fd);
    //    EVP_PKEY_free(serverKey);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
