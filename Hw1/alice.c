#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>


unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

int main(int argc, char *argv[]) {
    if (argc < 3) {
       
        return 1;
    }

    int message_len = 0;
    //read message from input file 
    unsigned char *message = Read_File(argv[1], &message_len);
    if (message_len < 32) {
        printf("Error: message length must be >= 32 bytes.\n");
        free(message);
        return 1;
    }

   //read the seed from the input file
    int seed_len = 0;
    unsigned char *seed = Read_File(argv[2], &seed_len);
    if (seed_len != 32) {
        printf("Error: shared seed length must be 32 bytes.\n");
        free(message);
        free(seed);
        return 1;
    }
    

    //generate the random number, convert it to hex then write it to the "key" file
    unsigned char *pseudoRandomNumber = PRNG(seed, seed_len, message_len);
    char *key_hex = malloc(2 * message_len + 1);
    Convert_to_Hex(key_hex, pseudoRandomNumber, message_len);
    Write_File("Key.txt", key_hex, 2 * message_len);
    

    //encrypt the message using the generated PRNG and write it to the "cyphertext" file
    unsigned char *cyphertext = malloc(message_len);
    for (int i = 0; i < message_len; i++) {
        cyphertext[i] = message[i] ^ pseudoRandomNumber[i];
    }
    char *cyphertext_hex = malloc(2 * message_len + 1);
    Convert_to_Hex(cyphertext_hex, cyphertext, message_len);
    Write_File("Ciphertext.txt", cyphertext_hex, 2 * message_len);



    //Alice haseds the message to compare to the hash of the plaintext made by bob
    unsigned char *hash = Hash_SHA256(message, message_len);
    char *hash_hex = malloc(2 * SHA256_DIGEST_LENGTH + 1);
    Convert_to_Hex(hash_hex, hash, SHA256_DIGEST_LENGTH);

    
 //reads bobs hash from the hash file and compares it with the hashed msg by alice to see if they match
    int bobs_hash_length = 0;
    unsigned char *bobs_hash = Read_File("Hash.txt", &bobs_hash_length);

    int verify_match = 0;
    if (bobs_hash_length == 2 * SHA256_DIGEST_LENGTH &&
        memcmp(bobs_hash, hash_hex, 2 * SHA256_DIGEST_LENGTH) == 0) {
        verify_match = 1;
    }

    if (verify_match) {
        Write_File("Acknowledgment.txt", "Acknowledgment Successful",
                (int)strlen("Acknowledgment Successful"));
    } else {
        Write_File("Acknowledgment.txt", "Acknowledgment Failed",
                (int)strlen("Acknowledgment Failed"));
    }


    // free the memory to make sure there are no leaks
    free(pseudoRandomNumber);
    free(hash);
    free(message);
    free(seed);
    free(hash_hex);
    free(bobs_hash);
    free(key_hex);
    free(cyphertext_hex);
    free(cyphertext);

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
    int temp_size = ftell(pFile) + 1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    fgets(output, temp_size, pFile);
    fclose(pFile);

    *fileLen = temp_size - 1;
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
