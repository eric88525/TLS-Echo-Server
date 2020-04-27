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

#define CA_FILE                "./CA/cacert.pem"
#define SERVER_KEY             "./server/key.pem"
#define SERVER_CERT            "./server/cert.pem"

void setCA(SSL_CTX *ctx){
	// SSL_VERIFY_PEER = verify both  
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

	if (SSL_CTX_load_verify_locations(ctx, CA_FILE, 0) != 1) {
		SSL_CTX_free(ctx);
		printf("Failed to load CA file %s", CA_FILE);
	}
	//load server cert
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}else{
		puts("load SERVER_CERT success");
	}
	// load server private key
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
		printf("load private key fail.\n");
		ERR_print_errors_fp(stdout);
		exit(1);
	}else{
		puts("load server private key success");
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
		printf("Client certificate:\n");
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
    char message[BUFSIZE+1] = {};
    char serverMessage[BUFSIZE+1]={};
    //socket的建立
    int server_fd = 0,client_fd = 0,c=0;
    server_fd = socket(AF_INET , SOCK_STREAM , 0);
    if (server_fd == -1){
        printf("Fail to create a socket.");
    }
	//socket的連線
    struct sockaddr_in serverInfo,clientInfo;
    bzero(&serverInfo,sizeof(serverInfo));
    //set server info and bind socket
    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverInfo.sin_port = htons(atoi(argv[1]));

    if( bind(server_fd,(struct sockaddr *)&serverInfo,sizeof(serverInfo)) < 0)
	{
		//print the error message
		perror("bind failed. Error");
		return 1;
	}
    listen(server_fd,2);

  	//SSL init
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new (TLSv1_2_server_method()); 
    //set ca about
	setCA(ctx);
    while(1){
    	puts("listening...");
        if ( (client_fd = accept(server_fd, (struct sockaddr*)&clientInfo, (socklen_t*)&c)) == -1 ){
				perror("accept");
				exit(1);
		}
		printf("Accept client\n");
		//start TLS
		SSL * ssl = SSL_new(ctx);;
		SSL_set_fd(ssl, client_fd);
		if (SSL_accept(ssl) == -1) {
			perror("accept");
			ERR_print_errors_fp(stderr);  
			close(client_fd);
			break;
		}
		showCert(ssl);
		memset(message,0,sizeof(message));
		memset(serverMessage,0,sizeof(message));
		strcpy(serverMessage,"Server got your message:_");
        SSL_read (ssl, message, sizeof(message));
        strcat(serverMessage,message);
        SSL_write(ssl,serverMessage,strlen(serverMessage));
        printf("%s","Receive message from client:_");
        printf("%s\n",message);
        SSL_shutdown(ssl);
		SSL_free(ssl);
    }
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}