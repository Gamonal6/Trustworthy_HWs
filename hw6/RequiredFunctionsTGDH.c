/*

    Tree-based Group Diffie-Hellman (TGDH)
    HWX Required Functions

    DH Group: RFC 2409 Group 2 (1024-bit MODP)
    p = FFFFFFFFFFFFFFFFC90FDAA22168C234...FFFFFFFFFFFFFFFF
    g = 2

    Library: OpenSSL BIGNUM (libssl, libcrypto)
    Documentation: https://www.openssl.org/docs/manmaster/man3/

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

/*
   File I/O Functions  
 */

/* Read entire file as string, strip trailing whitespace */
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
    if (!buffer) { fclose(file); return NULL; }
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
           buffer[read_size-1] == '\r' || buffer[read_size-1] == ' '))
        buffer[--read_size] = '\0';
    *length = (int)read_size;
    fclose(file);
    return buffer;
}

/* Write string to file */
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

/* Read an integer from a file */
int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    int value = atoi(str);
    free(str);
    return value;
}

/* 
Read multi-line file into array of strings (one per line).
Returns number of lines read. Caller must free each line and the array
*/
int Read_Lines(const char *filename, char ***lines_out) {
    FILE *f = fopen(filename, "r");
    if (!f) { fprintf(stderr, "Error: Cannot open %s\n", filename); return 0; }
    
    char **lines = NULL;
    int count = 0;
    char buf[1024];
    
    while (fgets(buf, sizeof(buf), f)) {
        /* Strip newline/whitespace */
        int len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
            buf[--len] = '\0';
        if (len == 0) continue;  /* skip blank lines */
        
        lines = realloc(lines, (count + 1) * sizeof(char*));
        lines[count] = strdup(buf);
        count++;
    }
    
    fclose(f);
    *lines_out = lines;
    return count;
}


/* 
   Hex Conversion Functions  
*/

/* Print data as hex */
void Print_Hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* Convert byte array to hex string */
void Bytes_to_Hex(char *output, const unsigned char *input, int inputlength) {
    for (int i = 0; i < inputlength; i++)
        sprintf(&output[2*i], "%02x", input[i]);
    output[inputlength * 2] = '\0';
}
