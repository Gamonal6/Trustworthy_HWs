
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>


char* Read_File(const char *filename, int *length);
int Write_File(const char *filename, const char *data);
int Read_Int_From_File(const char *filename);


int main(int argc, char *argv[]) {
    if (argc != 3) 
    
    {
        printf("Invalid num of arguments\n");
        return 1;
    }


    // read the challenge from the file
    int chall_len = 0;
    char *challenge_hex = Read_File(argv[1], &chall_len);
    if (!challenge_hex) 
    {
        printf("cant read file\n");
        return 1;
    }

    //read difficulty
    int diff_len = 0;
    char *diff_str = Read_File(argv[2], &diff_len);
    if (!diff_str) 
    {
        printf("cant read file\n");
        free(challenge_hex);
        return 1;
    }

    //Write the challenge to the file

    if (Write_File("puzzle_challenge.txt", challenge_hex) != 0) 
    {
        printf("cant write file\n");
        free(challenge_hex);
        free(diff_str);
        return 1;
    }

    if (Write_File("puzzle_k.txt", diff_str) != 0) 
    {
        printf("cant write file\n");
        free(challenge_hex);
        free(diff_str);
        return 1;
    }

    free(challenge_hex);
    free(diff_str);
    return 0;
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

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}