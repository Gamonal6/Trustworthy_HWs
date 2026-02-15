#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define SHA256_LEN 32

// Helper prototypes
char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
void Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output);

// Builds a Merkel tree over 8 messages
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: ./mht <MessagesFile> <M_Index>\n");
        return 1;
    }

    int fileLen;
    char *fileContent = Read_File(argv[1], &fileLen);
    if (!fileContent) {
        printf("Error: Could not read file %s\n", argv[1]);
        return 1;
    }

    // Parse 8 msgs, skip line endings
    unsigned char *msgs[8];
    char *ptr = fileContent;
    
    for(int i = 0; i < 8; i++) {
        msgs[i] = (unsigned char*)ptr;
        
        ptr += 32;
        
        while (*ptr == '\r' || *ptr == '\n') {
            ptr++;
        }
    }

    unsigned char leaves[8][SHA256_LEN];
    unsigned char level1[4][SHA256_LEN];
    unsigned char level2[2][SHA256_LEN];
    unsigned char root[SHA256_LEN];

    for(int i = 0; i < 8; i++) {
        Compute_SHA256(msgs[i], 32, leaves[i]);
    }

    for(int i = 0; i < 4; i++) {
        unsigned char buffer[64]; 
        memcpy(buffer, leaves[2*i], 32);
        memcpy(buffer + 32, leaves[2*i+1], 32);
        Compute_SHA256(buffer, 64, level1[i]);
    }

    for(int i = 0; i < 2; i++) {
        unsigned char buffer[64];
        memcpy(buffer, level1[2*i], 32);
        memcpy(buffer + 32, level1[2*i+1], 32);
        Compute_SHA256(buffer, 64, level2[i]);
    }

    unsigned char buffer[64];
    memcpy(buffer, level2[0], 32);
    memcpy(buffer + 32, level2[1], 32);
    Compute_SHA256(buffer, 64, root);

    // Write root and path files
    char rootHex[65];
    Bytes_to_Hex(root, 32, rootHex);
    Write_File("TheRoot.txt", rootHex);
    
    char *idxStr = argv[2];
    int targetIdx = idxStr[1] - '1'; 

    if (targetIdx >= 0 && targetIdx <= 7) {
        char pathHex[1024] = ""; 
        char tempHex[65];

        // Sibilng hashes for auth path
        int neighborIdx = (targetIdx % 2 == 0) ? targetIdx + 1 : targetIdx - 1;
        Bytes_to_Hex(leaves[neighborIdx], 32, tempHex);
        strcat(pathHex, tempHex);
        strcat(pathHex, "\n");
        
        int currentIdx = targetIdx / 2; 
        neighborIdx = (currentIdx % 2 == 0) ? currentIdx + 1 : currentIdx - 1;
        
        Bytes_to_Hex(level1[neighborIdx], 32, tempHex);
        strcat(pathHex, tempHex); 
        strcat(pathHex, "\n");

        currentIdx = currentIdx / 2;
        neighborIdx = (currentIdx % 2 == 0) ? currentIdx + 1 : currentIdx - 1;

        Bytes_to_Hex(level2[neighborIdx], 32, tempHex);
        strcat(pathHex, tempHex);
        strcat(pathHex, "\n");

        Write_File("ThePath.txt", pathHex);
    }

    free(fileContent);
    return 0;
}

// Helper funcs

// Read whole file into a buffer
char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) return NULL;
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) { fclose(file); return NULL; }
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    *length = read_size;
    fclose(file);
    return buffer;
}

// Write string to file
int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) return -1;
    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

// Bytes to hex string
void Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
}

// Compute SHA-256 for data into outpt
int Compute_SHA256(const unsigned char *data, int data_len, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) return -1;
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) return -1;
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, output, &len) != 1) return -1;
    EVP_MD_CTX_free(ctx);
    return 0;
}