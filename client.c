#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define BUFSIZE 1024

#define CA_FILE       "ca/ca-cert.pem"
#define CLIENT_KEY    "client/client-private.key"
#define CLIENT_CERT   "client/client-cert.pem"

void setCA(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, 0) != 1) {
        perror("Failed to load CA file");
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    } else {
        puts("Loaded CLIENT_CERT successfully");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load private key");
        ERR_print_errors_fp(stdout);
        exit(1);
    } else {
        puts("Loaded CLIENT_KEY successfully");
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Certificate and private key do not match");
        ERR_print_errors_fp(stdout);
        exit(1);
    } else {
        puts("Certificate and private key match!");
    }
}

void showCert(SSL *ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("1. subject_name: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("2. issuer_name: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    } else {
        printf("No Cert exists!\n");
    }
    printf("Cipher type: %s\n", SSL_get_cipher(ssl));
}

int main(int argc, char *argv[]) {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    setCA(ctx);

    SSL *ssl = SSL_new(ctx);

    int sockfd = 0;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        perror("Fail to create a socket.");
        exit(1);
    }

    struct sockaddr_in info;
    bzero(&info, sizeof(info));
    info.sin_family = PF_INET;
    info.sin_addr.s_addr = inet_addr("127.0.0.1");
    info.sin_port = htons(atoi(argv[1]));

    int err = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
    if (err == -1) {
        perror("Connection error");
        exit(1);
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        perror("SSL connect fail!");
        ERR_print_errors_fp(stdout);
        exit(1);
    } else {
        puts("SSL connect success!");
    }

    showCert(ssl);

    char message[BUFSIZE+1]={};

    while (1) {
        printf("Enter a message (or 'exit' to quit): ");
        fgets(message, BUFSIZE, stdin);
        message[strcspn(message, "\n")] = '\0'; // Remove trailing newline

        if (strcmp(message, "exit") == 0) {
            break; // Exit the loop
        }

        SSL_write(ssl, message, strlen(message));

        memset(message, 0, sizeof(message));
        SSL_read(ssl, message, sizeof(message));
        printf("Received message from server: %s\n", message);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
