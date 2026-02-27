#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Read_Int_From_File(const char *filename);

void HMAC_SHA256(unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char out[32]);
int AES_CTR_Crypt(unsigned char *key, unsigned char *iv, unsigned char *in, int inlen, unsigned char *out, int encrypt);

int main(int argc, char *argv[]) {
    if (argc < 2) 
    {
        return 1;
    }

    const char *seed_path = argv[1];
    const char *cipher_path = "Ciphertexts.txt";
    const char *agg_path = "AggregatedHMAC.txt";

    if (argc >= 4)
    {
        cipher_path = argv[2];
        agg_path = argv[3];
    }

    //read the seed from the input file
    int seed_len = 0;
    unsigned char *seed = Read_File((char*)seed_path, &seed_len);
    seed_len = (int)strcspn((char*)seed, "\r\n");

    if (seed_len != 32) 
    {
        printf("shared seed must be 32 bytes\n");
        free(seed);
        return 1;
    }

    //generate the initial key from the shared seed
    unsigned char *key = PRNG(seed, seed_len, 32);

    //read aggregated hmac from input file
    int agg_len = 0;
    unsigned char *agg_hex_in = Read_File((char*)agg_path, &agg_len);
    agg_len = (int)strcspn((char*)agg_hex_in, "\r\n");
    if (agg_len != 64)
    {
        printf("aggregated hmac must be 64 hex characters\n");
        free(seed);
        free(key);
        free(agg_hex_in);
        return 1;
    }

    unsigned char received_agg[32];
    Hex_to_Bytes((char*)agg_hex_in, received_agg, agg_len);

    //read ciphertexts from input file line by line
    FILE *cipherFile = fopen(cipher_path, "r");
    if (cipherFile == NULL)
    {
        printf("Error opening file.\n");
        free(seed);
        free(key);
        free(agg_hex_in);
        return 1;
    }

    unsigned char *ciphertexts = NULL;
    unsigned char *all_keys = NULL;
    int message_count = 0;
    char line[1024 * 2 + 3];

    unsigned char hmac[32];
    unsigned char *agg = NULL;

    while (fgets(line, sizeof(line), cipherFile))
    {
        int line_len = (int)strcspn(line, "\r\n");
        if (line_len != 1024 * 2)
        {
            printf("ciphertext line must be 2048 hex characters\n");
            free(seed);
            free(key);
            free(agg_hex_in);
            free(ciphertexts);
            free(all_keys);
            free(agg);
            fclose(cipherFile);
            return 1;
        }

        unsigned char *temp_c = realloc(ciphertexts, (message_count + 1) * 1024);
        unsigned char *temp_k = realloc(all_keys, (message_count + 1) * 32);
        if (!temp_c || !temp_k)
        {
            printf("Error allocating memory.\n");
            free(seed);
            free(key);
            free(agg_hex_in);
            free(ciphertexts);
            free(all_keys);
            free(agg);
            fclose(cipherFile);
            return 1;
        }

        ciphertexts = temp_c;
        all_keys = temp_k;

        Hex_to_Bytes((char*)line, ciphertexts + (message_count * 1024), line_len);
        memcpy(all_keys + (message_count * 32), key, 32);

        //compute individual HMAC
        HMAC_SHA256(key, 32, ciphertexts + (message_count * 1024), 1024, hmac);

        //aggregate HMACs
        if (message_count == 0)
        {
            agg = Hash_SHA256(hmac, 32);
        }
        else
        {
            unsigned char concat[32 * 2];
            memcpy(concat, agg, 32);
            memcpy(concat + 32, hmac, 32);
            unsigned char *new_agg = Hash_SHA256(concat, sizeof(concat));
            free(agg);
            agg = new_agg;
        }

        //update key for next message
        unsigned char *new_key = Hash_SHA256(key, 32);
        free(key);
        key = new_key;

        message_count++;
    }

    fclose(cipherFile);

    if (message_count == 0)
    {
        printf("ciphertexts file is empty\n");
        free(seed);
        free(key);
        free(agg_hex_in);
        free(ciphertexts);
        free(all_keys);
        free(agg);
        return 1;
    }

    //verify aggregate hmac
    if (memcmp(agg, received_agg, 32) != 0)
    {
        printf("Aggregated HMAC verification failed. No decryption performed.\n");
        free(seed);
        free(key);
        free(agg_hex_in);
        free(ciphertexts);
        free(all_keys);
        free(agg);
        return 1;
    }

    //decrypt ciphertexts and write plaintexts
    unsigned char *plaintexts = malloc((message_count * 1024) + (message_count - 1));
    if (!plaintexts)
    {
        printf("Error allocating memory.\n");
        free(seed);
        free(key);
        free(agg_hex_in);
        free(ciphertexts);
        free(all_keys);
        free(agg);
        return 1;
    }

    int plain_pos = 0;
    unsigned char plain[1024];

    for (int i = 0; i < message_count; i++)
    {
        AES_CTR_Crypt(all_keys + (i * 32), (unsigned char*)"abcdefghijklmnop", ciphertexts + (i * 1024), 1024, plain, 0);
        memcpy(plaintexts + plain_pos, plain, 1024);
        plain_pos += 1024;
        if (i < message_count - 1) plaintexts[plain_pos++] = '\n';
    }

    Write_File("Plaintexts.txt", (char*)plaintexts, plain_pos);

    // free the memory to make sure there are no leaks
    free(seed);
    free(key);
    free(agg_hex_in);
    free(ciphertexts);
    free(all_keys);
    free(agg);
    free(plaintexts);

    return 0;
}


/*************************************************************
					F u n c t i o n s
**************************************************************/

/*============================
        Read from File
==============================*/
unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile;
    pFile = fopen(fileName, "r");
    if (pFile == NULL)
    {
        printf("Error opening file.\n");
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    fgets(output, temp_size, pFile);
    fclose(pFile);

    *fileLen = temp_size-1;
    return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  //fputs(input, pFile);
  fwrite(input, 1, input_length, pFile);
  fclose(pFile);
}

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex (char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

/*============================
        Convert to Hex 
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    printf("Hex format: %s\n", output);  //remove later
}

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

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    unsigned char nonce[16] = {0};

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);

    unsigned char zeros[prnglen];
    memset(zeros, 0, prnglen);

    int outlen;
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);

    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}

/*============================
        SHA-256 Fucntion
==============================*/
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return hash;
}

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File((char*)filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

/*============================
        HMAC-SHA256 Fucntion
==============================*/
void HMAC_SHA256(unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char out[32])
{
    unsigned int outlen = 0;
    HMAC(EVP_sha256(), key, keylen, data, datalen, out, &outlen);
}

/*============================
        AES-CTR Fucntion
==============================*/
int AES_CTR_Crypt(unsigned char *key, unsigned char *iv, unsigned char *in, int inlen, unsigned char *out, int encrypt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error allocating memory.\n");
        exit(0);
    }

    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, encrypt);

    int outlen1 = 0;
    int outlen2 = 0;
    EVP_CipherUpdate(ctx, out, &outlen1, in, inlen);
    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);

    EVP_CIPHER_CTX_free(ctx);
    return outlen1 + outlen2;
}