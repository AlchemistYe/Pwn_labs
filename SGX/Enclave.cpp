#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

// RC4 decryption implementation in Intel SGX
const char* k = "gosecgosec";
unsigned char* key = (unsigned char*)k;
unsigned char K[256];
unsigned char S[256];
unsigned char keystream[256];
unsigned char plaintext[256];

void ecall_sbox_generation()
{
    for (int i = 0; i < 256; ++i)
    {
        S[i] = i;
        K[i] = key[i % 10];
    }
    int j = 0;
    for (int i = 0; i < 256; ++i)
    {
        j = (j + S[i] + K[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

void ecall_keystream_generation()
{
    int i = 0;
    int j = 0;
    for (int k = 0; k < 256; ++k)
    {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        int t = (S[i] + S[j]) % 256;
        keystream[k] = S[t];
    }
}

void ecall_decryption(unsigned char* ciphertext, size_t len)
{
    const char* temp = reinterpret_cast<const char*>(ciphertext);
    for (int i = 0; i < strlen(temp); ++i)
    {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
    printf("plaintext: %s\n", plaintext);
}

