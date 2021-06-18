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
#include <sys/stat.h>
#include <ifaddrs.h>
#include <netinet/in.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"demoCA/private/cacert.pem"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFF_SIZE 2000

int createTunDevice();					//TUN0 interface open
SSL* SSL_Init();					//SSL initialization
int setupTCPServer();					//TCP server initialization
void processRequest(SSL * ssl, int sock, int tunfd, int pipefd);//TLS Data Processing
void tunPipeSelected(int tunfd);			//Deal with TUN
void pipeSelected(int pipefd, SSL *ssl);		//Deal with Pipe
void sockSelected(int tunfd, SSL *ssl, int sock);	//Deal with tunnel
void IsEndPacket(char buff[], SSL* ssl, int sockfd);	//Deal with end packet
int Userauthentication(SSL *ssl, int sock);		//User anthentication and create a pipe for every clientip 
void closeSSLAndSocket(SSL *ssl, int newsock);		//As function name


int main(){
	/*Varible definition*/
	int tunfd;
	int tcp_listen_sock;
	SSL *ssl;
	pid_t pid;

	/*TUN0 interface initialization*/
	tunfd = createTunDevice();
	system("sudo ifconfig tun0 192.168.53.1/24 up");
	
	/*fork child process*/
	if((pid = fork()) == -1) {
	      	perror("fork");
      		exit(1);
   	}

	/*Parent process listen to the TUN0 interface*/
	if(pid>0){
		daemon(1,1);
		while(1){
			printf("This is listen process\n");
			fd_set readFDSet;
			FD_ZERO(&readFDSet);
			FD_SET(tunfd,&readFDSet);
         		select(FD_SETSIZE,&readFDSet,NULL,NULL,NULL);

			if (FD_ISSET(tunfd,&readFDSet))
				tunPipeSelected(tunfd);
		}
		printf("I am over\n");
		exit(0);
	}

	else{
	/*TCP server initialization*/
	struct sockaddr_in sa_client;
	size_t client_len = sizeof(struct sockaddr_in);
	tcp_listen_sock = setupTCPServer();
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

			/*TLS initialization*/	
			ssl=SSL_Init();

			/*TLS connection/handshake*/
			SSL_set_fd(ssl, sock);
			int err=SSL_accept(ssl);
			fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("SSL connection established!\n");

			/*User Authentication*/
			int pipefd = Userauthentication(ssl,sock);
			printf("In child process,pipefd is %d\n",pipefd);

			/*TLS Data Processing*/
			processRequest(ssl,sock,tunfd,pipefd);
			closeSSLAndSocket(ssl,sock);
			close(sock);
			return 0;
		}
		else{	//Parent process
			/*Wait for next TCP connection*/
			close(sock);
		}
		
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

void processRequest(SSL *ssl, int sock, int tunfd, int pipefd)
{
	while(1) {
         	fd_set readFDSet;
         	FD_ZERO(&readFDSet);
         	FD_SET(pipefd,&readFDSet);
		FD_SET(sock,&readFDSet);	
         	select(FD_SETSIZE,&readFDSet,NULL,NULL,NULL);

         	if(FD_ISSET(pipefd,&readFDSet))
			pipeSelected(pipefd,ssl);
		if(FD_ISSET(sock,&readFDSet))	
			sockSelected(tunfd,ssl,sock);
	}
}

void pipeSelected(int pipefd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	bzero(buff, BUFF_SIZE);
	len=read(pipefd, buff, BUFF_SIZE-1);
	buff[len]='\0';
	printf("Got a packet from pipe:%d, packet length: %d\n",pipefd,len);

	SSL_write(ssl,buff,len);
}

void sockSelected(int tunfd, SSL *ssl, int sock)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");
	bzero(buff, BUFF_SIZE);
	len=SSL_read(ssl,buff,BUFF_SIZE-1);
	buff[len]='\0';
	
	/*Ending Packet Judgement*/
	IsEndPacket(buff,ssl,sock);
	write(tunfd,buff,len);
}

void IsEndPacket(char buff[], SSL* ssl, int sockfd)
{
	if((buff[0]=='\0')){
        	printf("Connection Termination\n");
        	SSL_shutdown(ssl);
      		SSL_free(ssl);
		close(sockfd);
		exit(0);
    	}
	return;
}

int Userauthentication(SSL *ssl,int sock)
{
	/*Receive Data*/	
	char username[BUFF_SIZE]={'\0'};
	char password[BUFF_SIZE]={'\0'};
	char clientip[BUFF_SIZE]={'\0'};
	char recvbuf[BUFF_SIZE];

	bzero(recvbuf,BUFF_SIZE);
	int recvlen=SSL_read(ssl,recvbuf,BUFF_SIZE-1);
	recvbuf[recvlen]='\0';
	
	printf("get sslmessage: %s\n",recvbuf);

	/*Divide the string to username , password and */ 
	char* pch;
  	pch = strtok(recvbuf, ":");
  	if (pch != NULL) {
     		strcpy(username, pch);
     		pch = strtok(NULL, ":");
  	} 
  	if (pch != NULL) {
    		strcpy(password, pch);
		pch = strtok(NULL, ":");
  	}
	if (pch != NULL) {
    		strcpy(clientip, pch);
  	}
	printf("username : %s\n", username); 
	printf("password : %s\n", password); 
	printf("clientip : %s\n", clientip);

	/*Password Check*/
	struct spwd *pw; 
	char *epasswd;
	pw = getspnam(username); 
	if (pw == NULL) { 
		exit(0); 
	} 
	printf("Login name: %s\n", pw->sp_namp); 
	printf("Passwd: %s\n", pw->sp_pwdp); 
	epasswd=crypt(password, pw->sp_pwdp); 

	if (strcmp(epasswd, pw->sp_pwdp)) { //anthentication failed
		printf("Authentication Failed.Password entered doesn't match\n");
		char response_failed[]="authentication failed";
		printf("authentication failed\n");
		SSL_write(ssl,response_failed,strlen(response_failed));
		closeSSLAndSocket(ssl,sock);
		exit(0); 
	}
	//anthentication succeed
	char response_succeed[]="authentication succeed";
	printf("authentication succeed\n");
	SSL_write(ssl,response_succeed,strlen(response_succeed));

	/*FIFO Create*/
	if(mkfifo(clientip, 0666) < 0){
		if(errno != EEXIST){
			perror("Create FIFO Failed\n");
			exit(1);
		}
	}
	int read_fd = open(clientip,O_RDONLY|O_NONBLOCK);
	if(read_fd < 0){
		printf("read_fd = %d\n",read_fd);
        	perror("open failed\n");
		exit(1);
    	}
	printf("read_fd = %d\n",read_fd);
	printf("open success\n");
	printf("%s pipefd is %d\n",clientip,read_fd);
	
	return read_fd;
}

void closeSSLAndSocket(SSL *ssl, int newsock)
{
   	if(ssl!=NULL) {
      		SSL_shutdown(ssl);
      		SSL_free(ssl);
   	}
   	close(newsock);
}

void tunPipeSelected(int tunfd)
{
	int len;
	char buff[BUFF_SIZE];
	char clientip[BUFF_SIZE];

	printf("Got a packet from TUN0\n");
	bzero(buff, BUFF_SIZE);
	len=read(tunfd, buff, BUFF_SIZE-1);
	buff[len]='\0';

	/*Get IP destination*/
	if(len < 20 || buff[0] != 0x45)
		return;
	unsigned char x;
	bzero(clientip, BUFF_SIZE);
	x=buff[16];
	sprintf(clientip,"%u.",x);

	x=buff[17];
	sprintf(clientip+strlen(clientip),"%u.",x);

	x=buff[18];
	sprintf(clientip+strlen(clientip),"%u.",x);

	x=buff[19];
	sprintf(clientip+strlen(clientip),"%u",x);
	clientip[strlen(clientip)]='\0';
	printf("TUN ip dst: %s\n",clientip);	

	/*Write to named_pipe*/
	int write_fd = open(clientip,O_WRONLY|O_NONBLOCK);
	if(write_fd < 0){
		perror("open failed\n");
		return;
	}
	write(write_fd, buff, len);

}
