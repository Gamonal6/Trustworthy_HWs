#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>


//prototypes
char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex);

int Read_Int_From_File(const char *filename);
int Write_Int_To_File(const char *filename, int value);
void Print_Hex(const char *label, const unsigned char *data, int len);
static void nonce_tobytes(uint64_t value, unsigned char out[8]);
static int k_leading_zeroes(const unsigned char *hash, int k);


int main(int argc, char *argv[]) 
{
    if (argc != 3) 
    {
        printf("No filen provided\n");
        return 1;
    }
    int len_hex_chall = 0;
    char *hex_chall = Read_File(argv[1], &len_hex_chall); //read the challenge from the file

    if (!hex_chall) {
        printf("Cant read challenge file\n");
        return 1;
    }

    int num_k = Read_Int_From_File(argv[2]); //read the number of k from the file
    if (num_k <= 0) 
    {
        printf("Invalid k\n");
        free(hex_chall);
        return 1;
    }

    unsigned char chall_bytes[64];

    // convert the hex challange to byte format
    int chall_bytes_len = Hex_to_Bytes(hex_chall, chall_bytes, len_hex_chall);
    free(hex_chall);

    if (chall_bytes_len <= 0)
    {
        printf("Invalid challenge\n");
        return 1;
    }

    // actual data is the challenge bytes and the nonce bytes
    unsigned char actual_data[72];
    memcpy(actual_data, chall_bytes, (size_t)chall_bytes_len);

    uint64_t max_try = 1;
    //max try is 2^k
    for (int i = 0; i < num_k; i++) 
    {
        max_try *= 2;
    }

    uint64_t nonce = 0;
    uint64_t iterations = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int found = 0;


    //iterate through all the possible nonces
    while (max_try == 0 || nonce < max_try) 
    {
        unsigned char nonce_bt[8];
        nonce_tobytes(nonce, nonce_bt);
        memcpy(actual_data + chall_bytes_len, nonce_bt, 8);;
    
        SHA256(actual_data, (size_t)chall_bytes_len + 8, hash);
        iterations++;
    
        if (k_leading_zeroes(hash, num_k)) 
        {
            found = 1;
            break;
        }
        nonce++;
    }
    
    unsigned char out_nonce_bt[8];
    char nonce_hex[17];
    nonce_tobytes(nonce, out_nonce_bt); //convert the nonce to bytes
    Bytes_to_Hex(out_nonce_bt, 8, nonce_hex); //convert the nonce to hex

    if (Write_File("solution_nonce.txt", nonce_hex) != 0){
        printf("cant write the nonce to the file\n");
        return 1;
    } 

    char iterate_buf[32];
    sprintf(iterate_buf, "%llu", (unsigned long long)iterations);
    if (Write_File("solution_iterations.txt", iterate_buf) != 0) 
    {
        return 1;
    }
    return 0;
}



//NEw funtctions

static void nonce_tobytes(uint64_t value, unsigned char out[8]) {

    //LITTLE ENDIAN
    for (int i = 0; i < 8; i++) {
        out[i] = (unsigned char)value;  //least‑significant byte first
        value >>= 8;
    }
}

// Check if the first k bits of the hash are all zero
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




 // Read File
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

/*
    Hex Conversion Functions
*/

 // Convert hex string to byte array
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

 // Convert byte array to hex string
int Bytes_to_Hex(const unsigned char *bytes, int byte_len, char *hex) {
    for (int i = 0; i < byte_len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[byte_len * 2] = '\0';
    return byte_len * 2;
}

/*
    Cryptographic Functions
*/


/*
    Utility Functions
*/

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

int Write_Int_To_File(const char *filename, int value) {
    char buffer[32];
    sprintf(buffer, "%d", value);
    return Write_File(filename, buffer);
}

void Print_Hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
