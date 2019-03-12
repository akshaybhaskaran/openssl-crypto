#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <time.h>
#include <stdlib.h>
using namespace std;

int encrypt(unsigned char *plaintext, int plain_length, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);


int main(void){

    unsigned char *key = (unsigned char *) "01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char *plaintext = (unsigned char *)"This is an english plain text";
    unsigned char ciphertext[256];
    unsigned char decryptedtext[256];

    int decrypted_length, cipher_length;

    //Calling the encrypt method
    cipher_length = encrypt(plaintext, strlen((char*)plaintext), key, iv, ciphertext);
    cout << "Plaintext: " << plaintext << endl;
    cout << "Ciphertext: " <<  ciphertext << endl;

    //Calling the decrypt method
    //decrypted_length = decrypt(ciphertext, cipher_length, key, iv, decryptedtext);
    //decryptedtext[decrypted_length] = '\0';
    //cout << "Decrypted text is: " << decryptedtext;

    return 0;
}

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plain_length, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){

    EVP_CIPHER_CTX *ctx;
    int len, cipher_length;

    //Step # 1 - Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    //Step # 2 - Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    //Step # 3 - Update the encryption operation
    //Provide the plaintext to be encrypted
    //This can be called multiple times if necessary
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_length))
        handleErrors();
    cipher_length = len;


    //Step # 4 - Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    cipher_length += len;

    //Step # 5 - Clean up everything
    EVP_CIPHER_CTX_free(ctx); 

    return cipher_length;

}




