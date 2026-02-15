
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>


char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Read_Int_From_File(const char *filename);
static int k_leading_zeroes(const unsigned char *hash, int k);






int main(int argc, char *argv[]) {
    if (argc != 4) 
    {
        printf("Invalid num of arguments\n");
        return 1;
    }

    int chall_len = 0;
    char *challenge_hex = Read_File(argv[1], &chall_len); //read the challenge from the file
    if (!challenge_hex) return 1;

    //read the difficulty from the file
    int k = Read_Int_From_File(argv[2]);
    if (k < 0) 
    {
        free(challenge_hex);
        return 1;
    }
    
    //read the nonce from the file
    int nonce_hex_len = 0;
    char *nonce_hex = Read_File(argv[3], &nonce_hex_len);
    if (!nonce_hex) 
    {
        free(challenge_hex);
        return 1;
    }

    //convert the challenge from hex to bytes
    unsigned char challenge_bytes[64];
    int challenge_bytes_len = Hex_to_Bytes(challenge_hex, challenge_bytes, chall_len);
    free(challenge_hex);
    if (challenge_bytes_len <= 0) 
    {
        free(nonce_hex);
        return 1;
    }

    //convert the nonce from hex to bytes
    unsigned char nonce_bytes[8];
    int nonce_bytes_len = Hex_to_Bytes(nonce_hex, nonce_bytes, nonce_hex_len);
    free(nonce_hex);
    if (nonce_bytes_len != 8) 
    {
        return 1;
    }


//concatenate the challenge bytes and the nonce bytes
    unsigned char data[64 + 8];
    memcpy(data, challenge_bytes, (size_t)challenge_bytes_len);
    memcpy(data + challenge_bytes_len, nonce_bytes, 8);

    //hash the new data
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, (size_t)challenge_bytes_len + 8, hash);

    //check if the hash has k leading zeroes
    if (k_leading_zeroes(hash, k)) 
    {
        Write_File("verification_result.txt", "ACCEPT\n");
        return 0;
    } 
    else 
    {
        Write_File("verification_result.txt", "REJECT\n");
        return 1;
    }
}


static int k_leading_zeroes(const unsigned char *hash, int bits) 
{
    if (bits <= 0)
        return 1;


     //number of full zero bytes in the hash    
    int full_zero_bytes = bits / 8;
    int remaining_bits = bits % 8; //number of remaining bits in the last byte


    //loop through all the full zero bytes to check if they are acutally 0
    for (int i = 0; i < full_zero_bytes; ++i) 
    {
        if (hash[i] != 0)
            return 0;
    }

    //if there are no remaining bits, then the hash is all zero
    if (remaining_bits == 0)
        return 1;

        //placeholder for the last byte
    unsigned char placeholder = (unsigned char)(0xFF << (8 - remaining_bits));
    if ((hash[full_zero_bytes] & placeholder) != 0)
        return 0;
    return 1;
}


char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    
    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
                              buffer[read_size-1] == '\r' || 
                              buffer[read_size-1] == ' ')) {
        buffer[--read_size] = '\0';
    }
    
    *length = read_size;
    fclose(file);
    return buffer;
}

 // Write string to file
int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}


int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }
    
    int byte_len = hex_len / 2;
    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }
    
    return byte_len;
}

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}