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
#define CA_FILE             "./CA/cacert.pem"
#define CLIENT_KEY          "./client/key.pem"
#define CLIENT_CERT         "./client/cert.pem"

void setCA(SSL_CTX *ctx){
    // SSL_VERIFY_PEER = verify both  
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, 0) != 1) {
        SSL_CTX_free(ctx);
        printf("Failed to load CA file %s", CA_FILE);
    }
    //load server cert
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }else{
        puts("load CLIENT_CERT success");
    }
    // load server private key
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
        printf("load private key fail.\n");
        ERR_print_errors_fp(stdout);
        exit(1);
    }else{
        puts("load CLIENT_KEY success");
    }
    // check if cert and private key is ok
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }else{
        puts("cert and privateKey ok!");
    }
}
void showCert(SSL * ssl){
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("1.subject_name: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("2.issuer_name%s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No Cert exitst！\n");
    }
    puts("Cipher type");
    puts(SSL_get_cipher(ssl));
}
int main(int argc , char *argv[])
{

    //----------------------------------------------- ssl region
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new (TLSv1_2_client_method()); 
    setCA(ctx);
    SSL * ssl = SSL_new(ctx);
    //---------------------- --------------------------socket region

    //socket的建立
    int sockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        printf("Fail to create a socket.");
    }
    //socket的連線
    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;
    //localhost test
    info.sin_addr.s_addr = inet_addr("127.0.0.1");
    info.sin_port = htons(atoi(argv[1]));
    int err = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(err==-1){
        printf("Connection error");
    }
    //---------------------------------------------------------------
    SSL_set_fd(ssl,sockfd);
    if(SSL_connect(ssl)==-1){
        puts("SSL connect fail!");
    }else{
        puts("SSL connect success!");
        
    }
    showCert(ssl);
    //----------------------------------------------------------------
    char message[BUFSIZE+1]={};
    gets(message);
    SSL_write(ssl,message,strlen(message));
    SSL_read (ssl, message, sizeof(message));
    puts(message);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}