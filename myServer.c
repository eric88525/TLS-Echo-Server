#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define BUFSIZE 1024

#define CA_FILE       "./ca/ca-cert.pem"
#define SERVER_KEY    "./server/server-private.key"
#define SERVER_CERT   "./server/server-cert.pem"

void setCA(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, 0) != 1) {
        perror("Failed to load CA file");
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    } else {
        puts("Loaded SERVER_CERT successfully");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load private key");
        ERR_print_errors_fp(stdout);
        exit(1);
    } else {
        puts("Loaded server private key successfully");
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
        printf("Client certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("1. subject_name: %s\n", line);
        OPENSSL_free(line); // Free allocated memory
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("2. issuer_name: %s\n", line);
        OPENSSL_free(line); // Free allocated memory
        X509_free(cert);
    } else {
        printf("No Cert exists!\n");
    }
    printf("Cipher type: %s\n", SSL_get_cipher(ssl));
}

int main(int argc, char *argv[]) {
    char message[BUFSIZE + 1] = {};
    char serverMessage[BUFSIZE + 1] = {};
    int server_fd = 0, client_fd = 0, c = 0;
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Failed to create a socket");
        exit(1);
    }
    
    struct sockaddr_in serverInfo, clientInfo;
    bzero(&serverInfo, sizeof(serverInfo));
    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverInfo.sin_port = htons(atoi(argv[1]));
    
    if (bind(server_fd, (struct sockaddr *)&serverInfo, sizeof(serverInfo)) < 0) {
        perror("bind failed");
        exit(1);
    }
    listen(server_fd, 2);

    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    setCA(ctx);

    while (1) {
        puts("Listening...");
        if ((client_fd = accept(server_fd, (struct sockaddr *)&clientInfo, (socklen_t *)&c)) == -1) {
            perror("accept");
            continue; // Continue listening
        }
        printf("Accepted client\n");

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) == -1) {
            perror("SSL_accept");
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue; // Continue listening
        }

        showCert(ssl);

        memset(message, 0, sizeof(message));
        memset(serverMessage, 0, sizeof(serverMessage));
        strcpy(serverMessage, "Server got your message:_");
        SSL_read(ssl, message, sizeof(message));
        strcat(serverMessage, message);
        SSL_write(ssl, serverMessage, strlen(serverMessage));

        printf("Received message from client: %s\n", message);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
