#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len);
int Read_Int_From_File(const char *filename);

static unsigned char* Read_File_All(const char *fileName, size_t *fileLen);
static void Hash_SHA256_Out(const unsigned char *input, size_t inputlen, unsigned char out[SHA256_DIGEST_LENGTH]);
static void HMAC_SHA256(const unsigned char *key, int keylen, const unsigned char *data, size_t datalen, unsigned char out[32]);
static int AES_CTR_Crypt(const unsigned char *key, const unsigned char *iv,const unsigned char *in, int inlen, unsigned char *out, int encrypt);
static int is_hex_string(const unsigned char *buf, size_t len);
static unsigned char* Read_Seed(const char *fileName, size_t *seed_len);
static void Write_Hex_Line(FILE *f, unsigned char *data, size_t len, int add_newline);
static char** Split_Lines(unsigned char *buffer, size_t len, int *count);

int main(int argc, char *argv[]);

/*************************************************************
					F u n c t i o n s
**************************************************************/

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
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
	fgets((char*)output, temp_size, pFile);
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
    EVP_EncryptFinal_ex(ctx, pseudoRandomNumber, &outlen);

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
    char *str = (char*) Read_File((char*)filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

static unsigned char* Read_File_All(const char *fileName, size_t *fileLen)
{
    FILE *pFile = fopen(fileName, "rb");
    if (pFile == NULL) {
        fprintf(stderr, "Error opening file.\n");
        exit(1);
    }
    fseek(pFile, 0L, SEEK_END);
    long size = ftell(pFile);
    if (size < 0) {
        fprintf(stderr, "Error reading file size.\n");
        fclose(pFile);
        exit(1);
    }
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc((size_t)size + 1);
    if (!output) {
        fprintf(stderr, "Out of memory.\n");
        fclose(pFile);
        exit(1);
    }
    size_t read_len = fread(output, 1, (size_t)size, pFile);
    fclose(pFile);
    output[read_len] = '\0';
    *fileLen = read_len;
    return output;
}

static void Hash_SHA256_Out(const unsigned char *input, size_t inputlen, unsigned char out[SHA256_DIGEST_LENGTH])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

static void HMAC_SHA256(const unsigned char *key, int keylen, const unsigned char *data, size_t datalen, unsigned char out[32])
{
    unsigned int outlen = 0;
    HMAC(EVP_sha256(), key, keylen, data, datalen, out, &outlen);
}

static int AES_CTR_Crypt(const unsigned char *key, const unsigned char *iv,
                         const unsigned char *in, int inlen, unsigned char *out, int encrypt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }

    EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv, encrypt);
    int outlen1 = 0;
    int outlen2 = 0;
    EVP_CipherUpdate(ctx, out, &outlen1, in, inlen);
    EVP_CipherFinal_ex(ctx, out + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return outlen1 + outlen2;
}

static int is_hex_string(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)buf[i])) {
            return 0;
        }
    }
    return 1;
}

static unsigned char* Read_Seed(const char *fileName, size_t *seed_len)
{
    size_t len = 0;
    unsigned char *buf = Read_File_All(fileName, &len);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        len--;
    }

    if (len == 64 && is_hex_string(buf, len)) {
        unsigned char *seed = (unsigned char*) malloc(32);
        if (!seed) {
            fprintf(stderr, "Out of memory.\n");
            exit(1);
        }
        if (Hex_to_Bytes((const char*)buf, seed, (int)len) != 32) {
            fprintf(stderr, "Invalid seed hex length.\n");
            exit(1);
        }
        free(buf);
        *seed_len = 32;
        return seed;
    }

    if (len < 32) {
        fprintf(stderr, "Seed length must be 32 bytes.\n");
        exit(1);
    }

    unsigned char *seed = (unsigned char*) malloc(32);
    if (!seed) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }
    memcpy(seed, buf, 32);
    free(buf);
    *seed_len = 32;
    return seed;
}

static void Write_Hex_Line(FILE *f, unsigned char *data, size_t len, int add_newline)
{
    size_t hex_len = len * 2;
    char *hex = (char*) malloc(hex_len + 1);
    if (!hex) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }
    Convert_to_Hex(hex, data, (int)len);
    fwrite(hex, 1, hex_len, f);
    if (add_newline) {
        fwrite("\n", 1, 1, f);
    }
    free(hex);
}

static char** Split_Lines(unsigned char *buffer, size_t len, int *count)
{
    int c = 0;
    size_t i = 0;
    while (i < len) {
        while (i < len && (buffer[i] == '\n' || buffer[i] == '\r')) {
            i++;
        }
        if (i >= len) break;
        c++;
        while (i < len && buffer[i] != '\n' && buffer[i] != '\r') {
            i++;
        }
    }

    char **lines = (char**) malloc(sizeof(char*) * (size_t)c);
    if (!lines) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }

    i = 0;
    int idx = 0;
    while (i < len) {
        while (i < len && (buffer[i] == '\n' || buffer[i] == '\r')) {
            buffer[i] = '\0';
            i++;
        }
        if (i >= len) break;
        lines[idx++] = (char*)(buffer + i);
        while (i < len && buffer[i] != '\n' && buffer[i] != '\r') {
            i++;
        }
        if (i < len) {
            buffer[i] = '\0';
            i++;
        }
    }

    *count = c;
    return lines;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s Messages.txt SharedSeed.txt\n", argv[0]);
        return 1;
    }

    size_t seed_len = 0;
    unsigned char *seed = Read_Seed(argv[2], &seed_len);

    unsigned char *k = PRNG(seed, (unsigned long)seed_len, 32);
    free(seed);

    size_t msg_file_len = 0;
    unsigned char *messages = Read_File_All(argv[1], &msg_file_len);
    int line_count = 0;
    char **lines = Split_Lines(messages, msg_file_len, &line_count);
    if (line_count <= 0) {
        fprintf(stderr, "Messages file is empty.\n");
        free(messages);
        free(lines);
        free(k);
        return 1;
    }

    FILE *keys_f = fopen("Keys.txt", "wb");
    FILE *ciphers_f = fopen("Ciphertexts.txt", "wb");
    FILE *hmacs_f = fopen("IndividualHMACs.txt", "wb");
    if (!keys_f || !ciphers_f || !hmacs_f) {
        fprintf(stderr, "Error opening output files.\n");
        free(messages);
        free(k);
        return 1;
    }

    unsigned char agg[32];
    unsigned char hmac[32];
    unsigned char *cipher = (unsigned char*) malloc(1024);
    if (!cipher) {
        fprintf(stderr, "Out of memory.\n");
        free(messages);
        free(k);
        fclose(keys_f);
        fclose(ciphers_f);
        fclose(hmacs_f);
        return 1;
    }

    for (int i = 0; i < line_count; i++) {
        int line_len = (int)strlen(lines[i]);
        if (line_len != 1024) {
            fprintf(stderr, "Message length must be %d bytes on line %d.\n", 1024, i + 1);
            free(messages);
            free(lines);
            free(k);
            fclose(keys_f);
            fclose(ciphers_f);
            fclose(hmacs_f);
            free(cipher);
            return 1;
        }
        unsigned char *msg = (unsigned char*)lines[i];
        AES_CTR_Crypt(k, (unsigned char*)"abcdefghijklmnop", msg, 1024, cipher, 1);

        HMAC_SHA256(k, 32, cipher, 1024, hmac);

        if (i == 0) {
            Hash_SHA256_Out(hmac, 32, agg);
        } else {
            unsigned char concat[32 * 2];
            memcpy(concat, agg, 32);
            memcpy(concat + 32, hmac, 32);
            Hash_SHA256_Out(concat, sizeof(concat), agg);
        }

        int add_newline = (i < line_count - 1);
        Write_Hex_Line(keys_f, k, 32, add_newline);
        Write_Hex_Line(ciphers_f, cipher, 1024, add_newline);
        Write_Hex_Line(hmacs_f, hmac, 32, add_newline);

        unsigned char new_k[32];
        Hash_SHA256_Out(k, 32, new_k);
        memcpy(k, new_k, 32);
    }

    fclose(keys_f);
    fclose(ciphers_f);
    fclose(hmacs_f);

    char agg_hex[32 * 2 + 1];
    Convert_to_Hex(agg_hex, agg, 32);
    Write_File("AggregatedHMAC.txt", agg_hex, (int)strlen(agg_hex));

    free(cipher);
    free(messages);
    free(lines);
    free(k);

    return 0;
}