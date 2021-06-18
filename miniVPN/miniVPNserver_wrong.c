#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#include <termios.h>
#include <signal.h>
#include <shadow.h>
#include <crypt.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"wrongserver.crt"
#define KEYF	HOME"wrongserver.key"
#define CACERT	HOME"wrongcacert.pem"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFF_SIZE 2000

int createTunDevice();	//TUN0 interface open
SSL* SSL_Init();	//SSL initialization
int setupTCPServer();	//TCP server initialization
void processRequest(SSL * ssl, int sock, int tunfd);//TLS Data Processing
void tunSelected(int tunfd, SSL *ssl);	//Deal with Tun
void sockSelected(int tunfd, SSL *ssl, int sock);//Deal with tunnel
void IsEndPacket(char buff[], SSL* ssl, int sockfd);//Deal with end packet

int main(){
	/*Varible definition*/
	int tunfd;
	int tcp_listen_sock;
	SSL *ssl;

	/*TUN0 interface initialization*/
	tunfd=createTunDevice();
	system("sudo ifconfig tun0 192.168.53.1/24 up");

	/*TLS initialization*/	
	ssl=SSL_Init();

	/*TCP server initialization*/
	struct sockaddr_in sa_client;
	size_t client_len = sizeof(struct sockaddr_in);
	tcp_listen_sock=setupTCPServer();
	fprintf(stderr, "tcp_listen_sock = %d\n", tcp_listen_sock);
	
	daemon(1,1);
	while(1){
		/*TCP connection accept*/
		int sock = accept(tcp_listen_sock, (struct sockaddr *)&sa_client, &client_len);
		fprintf(stderr, "sock = %d\n", sock);
		if (sock==-1) {
			fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
			continue;
		}

		/*Create Child Process to keep the session*/
		if(fork()==0){	//Child process
			close(tcp_listen_sock);

			/* TLS connection/handshake */
			SSL_set_fd(ssl, sock);
			int err=SSL_accept(ssl);
			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");

			/* TLS Data Processing*/
			processRequest(ssl,sock,tunfd);
			close(sock);
			return 0;
		}
		else{	//Parent process
			/*Wait for next TCP connection*/
			close(sock);
		}
		
	}

	return 0;	
}

int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		exit(-1);
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		exit(-1);
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

SSL* SSL_Init() {
   	SSL_CTX* ctx;
   	SSL *ssl;
   	int err;

   	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
   
   	// Step 1: SSL context initialization
	ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection
	ssl = SSL_new(ctx);
   return ssl;
}

int setupTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);
	int err = bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}

void processRequest(SSL *ssl, int sock, int tunfd)
{
	while(1) {
         	fd_set readFDSet;
         	FD_ZERO(&readFDSet);
         	FD_SET(tunfd,&readFDSet);
		FD_SET(sock,&readFDSet);	
         	select(FD_SETSIZE,&readFDSet,NULL,NULL,NULL);
         	if(FD_ISSET(tunfd,&readFDSet))
			tunSelected(tunfd,ssl);
		if(FD_ISSET(sock,&readFDSet))	
			sockSelected(tunfd,ssl,sock);
	}
}

void tunSelected(int tunfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];
	printf("Got a packet from TUN0\n");
	bzero(buff, BUFF_SIZE);
	len=read(tunfd, buff, BUFF_SIZE);
	SSL_write(ssl,buff,len);
}

void sockSelected(int tunfd, SSL *ssl, int sock)
{
	int len;
	char buff[BUFF_SIZE];
	printf("Got a packet from the tunnel\n");
	len=SSL_read(ssl,buff,BUFF_SIZE);
	buff[len]='\0';
	
	/*Ending Packet Judgement*/
	IsEndPacket(buff,ssl,sock);
	write(tunfd,buff,len);

}

void IsEndPacket(char buff[], SSL* ssl, int sockfd){
	if((buff[0]=='\0')){
        printf("Connection Termination\n");
        SSL_shutdown(ssl);
      	SSL_free(ssl);
	close(sockfd);
	exit(0);
    }
}
