all: 
	gcc -o miniVPNclient miniVPNclient.c -lssl -lcrypto -lcrypt 
	gcc -o miniVPNserver miniVPNserver.c -lssl -lcrypto -lcrypt
	gcc -o miniVPNserver_wrong miniVPNserver_wrong.c -lssl -lcrypto -lcrypt
clean: 
	rm -f miniVPNclient miniVPNserver 
	rm -f *~

