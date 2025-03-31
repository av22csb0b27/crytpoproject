
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
#include <iomanip>
#include <openssl/rand.h>

using namespace std;

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define DELIMITER "|"
#define AES_KEY_SIZE 16  // 128-bit key
#define AES_BLOCK_SIZE 16
const size_t RSA_BLOCK_SIZE = 230; // 2048-bit RSA key block size

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
 //Function to print a BIGNUM in hexadecimal format
void print_bignum(const char *label, const BIGNUM *bn) {
    if (!bn) {
        std::cout << label << ": (null)" << std::endl;
        return;
    }

    char *hex = BN_bn2hex(bn);
    std::cout << label << ": " << hex << std::endl;
    OPENSSL_free(hex);  // Free memory allocated by BN_bn2hex
}

void printHex(const vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        cout << hex << setw(2) << setfill('0') << (int)byte;  // Print each byte in hex
    }
    cout << endl;
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        cerr << "Socket creation failed." << endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection to GA failed." << endl;
        return 1;
    }

    cout << "Connected to GA." << endl;

    // server:Receive key length first
    uint32_t serverkeySize;
    recv(client_fd, &serverkeySize, sizeof(serverkeySize), 0);
    serverkeySize = ntohl(serverkeySize);  // Convert from network to host byte order

    // Receive the actual public key
    char* serverPubKeyBuf = new char[serverkeySize + 1]();  // Allocate exact memory
    recv(client_fd, serverPubKeyBuf, serverkeySize, 0);
    serverPubKeyBuf[serverkeySize] = '\0';  // Null-terminate for safety

    // Convert received key back to EVP_PKEY*
    BIO* serverBio = BIO_new_mem_buf(serverPubKeyBuf, -1);
    EVP_PKEY* serverPublicKey = PEM_read_bio_PUBKEY(serverBio, nullptr, nullptr, nullptr);

    // Cleanup
    BIO_free(serverBio);
    delete[] serverPubKeyBuf;  // Free dynamically allocated memory

    if (!serverPublicKey) {
        cerr << "Failed to parse server's public key!" << endl;
        return 1;
    }

    cout << "Server's public key received successfully!" << endl;
    
    //printing the received public key
    printPublicKey(serverPublicKey);
    
    // Generate RSA Key Pair
    EVP_PKEY* keyPair = generateRSAKeyPair();
    EVP_PKEY* publicKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(publicKey, RSAPublicKey_dup(EVP_PKEY_get0_RSA(keyPair)));

    EVP_PKEY* privateKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(privateKey, RSAPrivateKey_dup(EVP_PKEY_get0_RSA(keyPair)));
    
    cout<<"exit of generation"<<endl;
    
    // Convert publicKey to PEM format and sending public key to the server
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, publicKey);
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    uint32_t keySize1 = htonl(pemLen);
    send(client_fd, &keySize1, sizeof(keySize1), 0);
    send(client_fd, pemData, pemLen, 0);
    BIO_free(bio);
    
    cout<<"Key size of the client: "<<keySize1<<endl;

    
    //calling the print function of the keys
    printPrivateKey(privateKey);
    printPublicKey(publicKey);
    
    //now we have to receive the share of the aes key from ga
    vector<unsigned char> receivedShare(AES_KEY_SIZE);
    ssize_t receivedBytes = recv(client_fd, receivedShare.data(), AES_KEY_SIZE, 0);

    if (receivedBytes != AES_KEY_SIZE) {
        cerr << "Error receiving AES key share! Expected " << AES_KEY_SIZE
             << " bytes but got " << receivedBytes << " bytes." << endl;
        exit(1);
    }

    cout << "Received AES key share successfully!" << endl;
    
    int request_type;
    while(true){
    cout<<"enter 0 for store, 1 for retrieve "<<endl;
    cin>>request_type;
    if(request_type == 0)
    {
        // Step 2: Input Message
        string message = "This is a large confidential message that needs encryption and authentication.";
        cout << "Original Message: " << message << endl;
        
        vector<unsigned char> hash;
        //    = sha256Hash(message);
        //    cout << "Computed SHA-256 Hash: " << vectorToString(hash) << endl;
        //
        //    message += "||" ;
        //    message += vectorToString(hash);
        message += "||vik.txt||user123";
        
        // Step 3: Compute Hash
        hash = sha256Hash(message);
        cout << "Computed SHA-256 Hash: " << vectorToString(hash) << endl;
        
        //sign the hash with private key
        vector<unsigned char> signature = rsaSign(privateKey, hash);
        cout << "Digital Signature: " << vectorToString(signature) << endl;
        
        
        // Step 5: Append Signature to Message
        vector<unsigned char> messageWithSignature(message.begin(), message.end());
        messageWithSignature.insert(messageWithSignature.end(), signature.begin(), signature.end());
        cout << "Decrypted before ecncryption hai mutu"<<endl;
        for (unsigned char c : messageWithSignature) {
            cout << hex << setw(2) << setfill('0') << (int)c << " ";
        }
        
        // Step 6: Encrypt with Public Key
        vector<unsigned char> encryptedMessage = rsaEncrypt(serverPublicKey, messageWithSignature);
        cout<<"Encrypted message from the client side minati: "<<endl;
        for (auto c : encryptedMessage)
            cout << hex << setw(2) << setfill('0') << (int)c << " ";
        cout << endl;
        //yaha tak kaam karaha hai
        
        //    cout << "Encrypted Message: " << vectorToString(encryptedMessage) << endl;
        
        
        // Send Encrypted Data to Server
        size_t totalSize = encryptedMessage.size();
        send(client_fd, &totalSize, sizeof(totalSize), 0); // Send total size first
        
        size_t sentBytes = 0;
        while (sentBytes < totalSize) {
            size_t chunkSize = std::min((size_t)4096, totalSize - sentBytes);
            ssize_t sent = send(client_fd, encryptedMessage.data() + sentBytes, chunkSize, 0);
            
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
        send(client_fd, &sigSize, sizeof(sigSize), 0);
        cout<<"The size of the signature sent from the client: "<<sigSize<<endl;
        
        char buffer[256];  // Buffer to receive the request message
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';  // Null-terminate to make it a valid C-string
            string receivedMessage(buffer);
            cout << "Received message: " << receivedMessage << endl;

            // If the received message is correct, send the stored AES key share
            if (receivedMessage == "Please send your AES key share.") {
                    send(client_fd, receivedShare.data(), receivedShare.size(), 0);
                    cout << "Sent AES key share to the server." << endl;
            }
        } else {
            cerr << "Error receiving message or connection closed." << endl;
        }
        
        
    }
    else if(request_type ==1){
        cout<<"RETRIEVAL PART OF THE CLIENT OKAY"<<endl;
        
        
        
        
        
        //retrieval part
        string user_id="user123";
        string filename="vik.txt";
        string retrieve_request = user_id + "||" + filename;
        //    vector<unsigned char> encrypted_request = rsaEncrypt(serverPublicKey, vector<unsigned char>(retrieve_request.begin(), retrieve_request.end()));
        
        
            vector<unsigned char> hash;
//        = sha256Hash(retrieve_request);
        //    cout << "Computed SHA-256 Hash: " << vectorToString(hash1) << endl;
        
        //    retrieve_request += "||" ;
        //    retrieve_request += vectorToString(hash1);
        
        // Step 3: Compute Hash
        hash = sha256Hash(retrieve_request);
        cout << "Computed SHA-256 Hash: " << vectorToString(hash) << endl;
        
        //sign the hash with private key
        vector<unsigned char> signature1 = rsaSign(privateKey, hash);
        cout << "Digital Signature: " << vectorToString(signature1) << endl;
        
        
        // Step 5: Append Signature to Message
        vector<unsigned char> messageWithSignature1(retrieve_request.begin(), retrieve_request.end());
        messageWithSignature1.insert(messageWithSignature1.end(), signature1.begin(), signature1.end());
        cout << "Decrypted before ecncryption hai mutu"<<endl;
        for (unsigned char c : messageWithSignature1) {
            cout << hex << setw(2) << setfill('0') << (int)c << " ";
        }
        
        // Step 6: Encrypt with Public Key
        vector<unsigned char> encryptedMessage1 = rsaEncrypt(serverPublicKey, messageWithSignature1);
        cout<<"Encrypted message from the client side minati: "<<endl;
        for (auto c : encryptedMessage1)
            cout << hex << setw(2) << setfill('0') << (int)c << " ";
        cout << endl;
        //yaha tak kaam karaha hai
        
        //    cout << "Encrypted Message: " << vectorToString(encryptedMessage) << endl;
        
        
        // Send Encrypted Data to Server
        size_t totalSize1 = encryptedMessage1.size();
        send(client_fd, &totalSize1,sizeof(totalSize1), 0); // Send total size first
        
        size_t sentBytes1 = 0;
        while (sentBytes1 < totalSize1) {
            size_t chunkSize = std::min((size_t)4096, totalSize1 - sentBytes1);
            ssize_t sent = send(client_fd, encryptedMessage1.data() + sentBytes1, chunkSize, 0);
            
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
        send(client_fd, &sigSize1, sizeof(sigSize1), 0);
        cout<<"The size of the signature sent from the client: "<<sigSize1<<endl;
        
        cout<<"client se bhejna wala part khatam hogaya"<<endl;
        //yaha tak sending wala part
        
        
        
        
        //sending part to the server
        char buffer[256];  // Buffer to receive the request message
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';  // Null-terminate to make it a valid C-string
            string receivedMessage(buffer);
            cout << "Received message: " << receivedMessage << endl;

            // If the received message is correct, send the stored AES key share
            if (receivedMessage == "Please send your AES key share.") {
                    send(client_fd, receivedShare.data(), receivedShare.size(), 0);
                    cout << "Sent AES key share to the server." << endl;
            }
        } else {
            cerr << "Error receiving message or connection closed." << endl;
        }
        
        
        
        
        
        
        //receiving the size of the signature from the server
        uint32_t sigSize2;
        recv(client_fd, &sigSize2, sizeof(sigSize2), 0);
        cout<<"The signature size received from the server is: "<<sigSize2<<endl;
        sigSize2 = ntohl(sigSize2);  // Convert from network to host byte order
        
        //receiving the size of data from the server
        size_t totalSize4;
        recv(client_fd, &totalSize4, sizeof(totalSize4), 0); // Receive total size first
        cout<<"total size 4"<<" "<<totalSize4<<endl;
        
        
        vector<unsigned char> encryptedData4(totalSize4);
        size_t receivedBytes = 0;
        
        while (receivedBytes < totalSize4) {
            size_t chunkSize = std::min((size_t)4096, totalSize4 - receivedBytes);
            ssize_t received = recv(client_fd, encryptedData4.data() + receivedBytes, chunkSize, 0);
            
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
        cout<<"decryption part suru"<<endl;
        vector<unsigned char> decryptedData4 = rsaDecrypt(privateKey, encryptedData4);
        string receivedMessage(decryptedData4.begin(), decryptedData4.end() - sigSize2);
        vector<unsigned char> receivedSignature(decryptedData4.end() - sigSize2, decryptedData4.end());
        cout<<"ab dekh yaha pe"<<endl;
        
        cout << "Decrypted Message: " << receivedMessage << endl;
        
        vector<string> messageParts = splitString(receivedMessage, "||");
        
        // Step 9: Print the extracted values
        cout<<"chalo receive karte hain"<<endl;
        cout << "\nExtracted Parts:\n";
        cout << "1. Original Message: " << messageParts[0] << endl;
        cout << "2. File Name: " << messageParts[1] << endl;
        cout << "3. User ID: " << messageParts[2] << endl;
        
        //Step 8: Verify Hash
        vector<unsigned char> receivedHash = sha256Hash(receivedMessage);
        if (rsaVerify(serverPublicKey, receivedHash, receivedSignature)) {
            cout << "✅ Signature Verification Passed!" << endl;
        } else {
            cout << "❌ Signature Verification Failed!" << endl;
        }
    }
    else{
        //send the share if you want to
        char buffer[256];  // Buffer to receive the request message
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';  // Null-terminate to make it a valid C-string
            string receivedMessage(buffer);
            cout << "Received message: " << receivedMessage << endl;
            
            // If the received message is correct, send the stored AES key share
            if (receivedMessage == "Please send your AES key share.") {
                int share;
                cout<<"enter 1 if you want to share your share "<<endl;
                cin>>share;
                if(share == 1){
                    send(client_fd, receivedShare.data(), receivedShare.size(), 0);
                    cout << "Sent AES key share to the server." << endl;
                }
            }
        } else {
            cerr << "Error receiving message or connection closed." << endl;
        }
    }

    }

    close(client_fd);
//    EVP_PKEY_free(clientKey);
//    EVP_PKEY_free(serverKey);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
