#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BUF_MEM*
base64_bytes(int size) {
    char *buf = malloc(size + 1), format[20];
    int chunk;
    BIO *b64, *out;
    BUF_MEM *bptr;

    // Create a base64 filter/sink
    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        return NULL;
    }

    // Create a memory source
    if ((out = BIO_new(BIO_s_mem())) == NULL) {
        return NULL;
    }

    // Chain them
    out = BIO_push(b64, out);
    //Ignore newlines - write everything in one line
    BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);

    // Generate random bytes
    if (!RAND_bytes(buf, size)) {
        return NULL;
    }

    BIO_write(out, buf, size);
    BIO_flush(out);
    BIO_get_mem_ptr(out, &bptr);
    BIO_set_close(out, BIO_NOCLOSE);
    BIO_free_all(out);

    return bptr;
}

int main() {
    BUF_MEM *mem = base64_bytes(32);
    if (mem != NULL) {
        char format[100];
        snprintf(format, sizeof format, "The size is %1$zu\n%%.%1$zus\n\n", mem->length);
        printf(format, mem->data);
    }
    
    // unsigned char buffer[33] = {}, *base64EncodeOutput;
    // int ret = RAND_bytes(buffer, sizeof buffer);

    // (void)Base64Encode(buffer, &base64EncodeOutput);
    // (void)printf("Return value of the operation was: %d\n%45s\n", ret, base64EncodeOutput);


    return EXIT_SUCCESS;
}
