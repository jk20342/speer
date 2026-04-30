#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int rc = system("openssl version >NUL 2>NUL");
    if (rc != 0) {
        puts("tls13_openssl_smoke: skipped (openssl not found)");
        return 0;
    }
    puts("tls13_openssl_smoke: openssl available");
    return 0;
}
