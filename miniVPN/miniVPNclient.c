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
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"demoCA/cacert.pem"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFF_SIZE 2000

int createTunDevice();						//TUN0 interface open
SSL* setupTLSClient(const char *hostname);			//TLS initialization
int setupTCPClient(const char *hostname, int port);		//TCP Client initialization
void tunSelected(int tunfd, SSL *ssl);				//Deal with Tun
void sockSelected(int tunfd, SSL *ssl, int sock);		//Deal with tunnel
void IsEndPacket(char buff[], SSL* ssl, int sockfd);		//Deal with end packet
int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx);	//Verify server.crt
void authentication(int tunfd, SSL *ssl);			//Verify user's identity 
void getLocalip(char *localip);					//get ip of tun0 

int main(int argc, char *argv[]){
	/*Varible Definition*/
	SSL *ssl;
	int tunfd;
	char *hostname="zzxsever";
	int port=4433;
	if (argc>1)
		hostname=argv[1];
	if (argc>2)
		port=atoi(argv[2]);
	
	/*TUN interface initialization*/
	tunfd=createTunDevice();
	system("sudo ifconfig tun0 192.168.53.6/24 up");
	system("sudo route add -net 192.168.60.0/24 tun0");

	/*TLS initialization*/
	ssl=setupTLSClient(hostname);

	/*TCP Client initialization*/
	int sockfd=setupTCPClient(hostname, port);

	/*TLS handshake*/
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err=SSL_connect(ssl);
	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/*User Authentication*/
	authentication(tunfd, ssl);
	
	
	daemon(1,1);
	/*Send/Receive Data*/
	while (1) {
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sockfd,&readFDSet);
		FD_SET(tunfd,&readFDSet);
		select(FD_SETSIZE,&readFDSet,NULL,NULL,NULL);

		if(FD_ISSET(tunfd,&readFDSet))
			tunSelected(tunfd,ssl);
		if(FD_ISSET(sockfd,&readFDSet))
			sockSelected(tunfd,ssl,sockfd);
	}

}

int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags=IFF_TUN | IFF_NO_PI;

	tunfd=open("/dev/net/tun", O_RDWR);
	if(tunfd==-1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret=ioctl(tunfd, TUNSETIFF, &ifr);
	if(ret==-1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_CTX *ctx;
	SSL *ssl;
	ctx=SSL_CTX_new(SSLv23_client_method());

	/*load cacert to verify server.crt*/
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	if (SSL_CTX_load_verify_locations(ctx,CACERT,NULL) < 1) {
        	printf("Error setting the verify locations. \n");
        	exit(0);
   	}
	
	ssl=SSL_new(ctx);
	X509_VERIFY_PARAM *vpm=SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set1_host(vpm,hostname,0);

	return ssl;
}

int setupTCPClient(const char *hostname, int port)
{
	struct sockaddr_in server_addr;

	// Get the IP address from hostname
	struct hostent *hp=gethostbyname(hostname);

	// Create a TCP socket
	int sockfd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information
	memset(&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	server_addr.sin_port=htons(port);
	server_addr.sin_family=AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

	return sockfd;
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

int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if(preverify_ok==1) {
		printf("Verification passed.\n");
	} 
	else{
		int err=X509_STORE_CTX_get_error(x509_ctx);
		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
		exit(0);
	}
}

void authentication(int tunfd, SSL *ssl){
	/*Account Information Input*/
	char username[BUFF_SIZE];
	char password[BUFF_SIZE];
	char localip[BUFF_SIZE];
	char sendbuf[BUFF_SIZE],recvbuf[BUFF_SIZE];
	
	memset(username,0,sizeof(username));
	memset(password,0,sizeof(password));
	memset(localip,0,sizeof(localip));

	printf("Please enter username: ");
	scanf("%s",username);
	getchar();

	printf("Please enter password: ");
	scanf("%s",password);
	getchar();	

	/*get localhost ip*/
	getLocalip(localip);
	
	/*Send Data*/
	bzero(sendbuf,BUFF_SIZE);
	bzero(recvbuf,BUFF_SIZE);
	int sendlen=sprintf(sendbuf,"%s:%s:%s",username,password,localip);
	sendbuf[sendlen]='\0';
	SSL_write(ssl,sendbuf,sendlen);

	/*Receive Data*/
	int recvlen=SSL_read(ssl,recvbuf,BUFF_SIZE-1);
	recvbuf[recvlen]='\0';
	
	/*Comparation*/
	if(strstr(recvbuf,"authentication succeed")!=NULL){
		printf("User authentication succeed\n");		
		return;
	}
	else{
		printf("User authentication failed on the server side.Terminating Connection\n");
		exit(0);
	}
}

void getLocalip(char *localip){
	int sockfd;
    	struct ifconf ifconf;
    	struct ifreq *ifreq;
    	char buf[512];
	
    	/*ifconf initialization*/
    	ifconf.ifc_len =512;
    	ifconf.ifc_buf = buf;
    	if ((sockfd =socket(AF_INET,SOCK_DGRAM,0))<0)
    	{
        	perror("socket" );
        	exit(1);
    	}
    	ioctl(sockfd, SIOCGIFCONF, &ifconf); 

	/*get tun0 ip*/
    	ifreq = (struct ifreq*)ifconf.ifc_buf;
    	for (int i=(ifconf.ifc_len/sizeof (struct ifreq)); i>0; i--)
	{
        	if(ifreq->ifr_flags == AF_INET){ 
	    		if(strcmp("tun0",ifreq->ifr_name)==0)
	    			strcpy(localip,inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr));	
            	ifreq++;
        	}
    	}
}
